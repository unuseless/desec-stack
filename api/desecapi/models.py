from __future__ import annotations

import binascii
import json
import logging
import re
import secrets
import string
import time
import uuid
from datetime import timedelta
from functools import cached_property
from hashlib import sha256

import dns
import psl_dns
import rest_framework.authtoken.models
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser
from django.contrib.postgres.constraints import ExclusionConstraint
from django.contrib.postgres.fields import CIEmailField, RangeOperators
from django.core.exceptions import ValidationError
from django.core.mail import EmailMessage, get_connection
from django.core.validators import RegexValidator
from django.db import models
from django.db.models import Manager, Q
from django.db.models.expressions import RawSQL
from django.template.loader import get_template
from django.utils import timezone
from django_prometheus.models import ExportModelOperationsMixin
from dns import rdata, rdataclass, rdatatype
from dns.exception import Timeout
from dns.rdtypes import ANY, IN
from dns.resolver import NoNameservers
from rest_framework.exceptions import APIException

from desecapi import metrics
from desecapi import pdns
from desecapi.dns import LongQuotedTXT, OPENPGPKEY

logger = logging.getLogger(__name__)
psl = psl_dns.PSL(resolver=settings.PSL_RESOLVER, timeout=.5)


def validate_lower(value):
    if value != value.lower():
        raise ValidationError('Invalid value (not lowercase): %(value)s',
                              code='invalid',
                              params={'value': value})


def validate_upper(value):
    if value != value.upper():
        raise ValidationError('Invalid value (not uppercase): %(value)s',
                              code='invalid',
                              params={'value': value})


class MyUserManager(BaseUserManager):
    def create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError('Users must have an email address')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(email, password=password)
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(ExportModelOperationsMixin('User'), AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = CIEmailField(
        verbose_name='email address',
        unique=True,
    )
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created = models.DateTimeField(auto_now_add=True)
    limit_domains = models.IntegerField(default=settings.LIMIT_USER_DOMAIN_COUNT_DEFAULT, null=True, blank=True)

    objects = MyUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def get_full_name(self):
        return self.email

    def get_short_name(self):
        return self.email

    def __str__(self):
        return self.email

    # noinspection PyMethodMayBeStatic
    def has_perm(self, *_):
        """Does the user have a specific permission?"""
        # Simplest possible answer: Yes, always
        return True

    # noinspection PyMethodMayBeStatic
    def has_module_perms(self, *_):
        """Does the user have permissions to view the app `app_label`?"""
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        """Is the user a member of staff?"""
        # Simplest possible answer: All admins are staff
        return self.is_admin

    def activate(self):
        self.is_active = True
        self.save()

    def change_email(self, email):
        old_email = self.email
        self.email = email
        self.validate_unique()
        self.save()

        self.send_email('change-email-confirmation-old-email', recipient=old_email)

    def change_password(self, raw_password):
        self.set_password(raw_password)
        self.save()
        self.send_email('password-change-confirmation')

    def delete(self):
        pk = self.pk
        ret = super().delete()
        logger.warning(f'User {pk} deleted')
        return ret

    def send_email(self, reason, context=None, recipient=None):
        fast_lane = 'email_fast_lane'
        slow_lane = 'email_slow_lane'
        immediate_lane = 'email_immediate_lane'
        lanes = {
            'activate': slow_lane,
            'activate-with-domain': slow_lane,
            'change-email': slow_lane,
            'change-email-confirmation-old-email': fast_lane,
            'password-change-confirmation': fast_lane,
            'reset-password': fast_lane,
            'delete-user': fast_lane,
            'domain-dyndns': fast_lane,
            'renew-domain': immediate_lane,
        }
        if reason not in lanes:
            raise ValueError(f'Cannot send email to user {self.pk} without a good reason: {reason}')

        context = context or {}
        content = get_template(f'emails/{reason}/content.txt').render(context)
        content += f'\nSupport Reference: user_id = {self.pk}\n'
        footer = get_template('emails/footer.txt').render()

        logger.warning(f'Queuing email for user account {self.pk} (reason: {reason}, lane: {lanes[reason]})')
        num_queued = EmailMessage(
            subject=get_template(f'emails/{reason}/subject.txt').render(context).strip(),
            body=content + footer,
            from_email=get_template('emails/from.txt').render(),
            to=[recipient or self.email],
            connection=get_connection(lane=lanes[reason], debug={'user': self.pk, 'reason': reason})
        ).send()
        metrics.get('desecapi_messages_queued').labels(reason, self.pk, lanes[reason]).observe(num_queued)
        return num_queued


validate_domain_name = [
    validate_lower,
    RegexValidator(
        regex=r'^(([a-z0-9_-]{1,63})\.)*[a-z0-9-]{1,63}$',
        message='Domain names must be labels separated by dots. Labels may consist of up to 63 letters, digits, '
                'hyphens, and underscores. The last label may not contain an underscore.',
        code='invalid_domain_name',
        flags=re.IGNORECASE
    )
]


class Domain(ExportModelOperationsMixin('Domain'), models.Model):
    @staticmethod
    def _minimum_ttl_default():
        return settings.MINIMUM_TTL_DEFAULT

    class RenewalState(models.IntegerChoices):
        IMMORTAL = 0
        FRESH = 1
        NOTIFIED = 2
        WARNED = 3

    created = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=191,
                            unique=True,
                            validators=validate_domain_name)
    owner = models.ForeignKey(User, on_delete=models.PROTECT, related_name='domains')
    published = models.DateTimeField(null=True, blank=True)
    minimum_ttl = models.PositiveIntegerField(default=_minimum_ttl_default.__func__)
    renewal_state = models.IntegerField(choices=RenewalState.choices, default=RenewalState.IMMORTAL)
    renewal_changed = models.DateTimeField(auto_now_add=True)
    _keys = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.pk is None and kwargs.get('renewal_state') is None and self.is_locally_registrable:
            self.renewal_state = Domain.RenewalState.FRESH

    @cached_property
    def public_suffix(self):
        try:
            public_suffix = psl.get_public_suffix(self.name)
            is_public_suffix = psl.is_public_suffix(self.name)
        except (Timeout, NoNameservers):
            public_suffix = self.name.rpartition('.')[2]
            is_public_suffix = ('.' not in self.name)  # TLDs are public suffixes
        except psl_dns.exceptions.UnsupportedRule as e:
            # It would probably be fine to treat this as a non-public suffix (with the TLD acting as the
            # public suffix and setting both public_suffix and is_public_suffix accordingly).
            # However, in order to allow to investigate the situation, it's better not catch
            # this exception. For web requests, our error handler turns it into a 503 error
            # and makes sure admins are notified.
            raise e

        if is_public_suffix:
            return public_suffix

        # Take into account that any of the parent domains could be a local public suffix. To that
        # end, identify the longest local public suffix that is actually a suffix of domain_name.
        for local_public_suffix in settings.LOCAL_PUBLIC_SUFFIXES:
            has_local_public_suffix_parent = ('.' + self.name).endswith('.' + local_public_suffix)
            if has_local_public_suffix_parent and len(local_public_suffix) > len(public_suffix):
                public_suffix = local_public_suffix

        return public_suffix

    def is_covered_by_foreign_zone(self):
        # Generate a list of all domains connecting this one and its public suffix.
        # If another user owns a zone with one of these names, then the requested
        # domain is unavailable because it is part of the other user's zone.
        private_components = self.name.rsplit(self.public_suffix, 1)[0].rstrip('.')
        private_components = private_components.split('.') if private_components else []
        private_domains = ['.'.join(private_components[i:]) for i in range(0, len(private_components))]
        private_domains = [f'{private_domain}.{self.public_suffix}' for private_domain in private_domains]
        assert self.name == next(iter(private_domains), self.public_suffix)

        # Determine whether domain is covered by other users' zones
        return Domain.objects.filter(Q(name__in=private_domains) & ~Q(owner=self._owner_or_none)).exists()

    def covers_foreign_zone(self):
        # Note: This is not completely accurate: Ideally, we should only consider zones with identical public suffix.
        # (If a public suffix lies in between, it's ok.) However, as there could be many descendant zones, the accurate
        # check is expensive, so currently not implemented (PSL lookups for each of them).
        return Domain.objects.filter(Q(name__endswith=f'.{self.name}') & ~Q(owner=self._owner_or_none)).exists()

    def is_registrable(self):
        """
        Returns False if the domain name is reserved, a public suffix, or covered by / covers another user's domain.
        Otherwise, True is returned.
        """
        self.clean()  # ensure .name is a domain name
        private_generation = self.name.count('.') - self.public_suffix.count('.')
        assert private_generation >= 0

        # .internal is reserved
        if f'.{self.name}'.endswith('.internal'):
            return False

        # Public suffixes can only be registered if they are local
        if private_generation == 0 and self.name not in settings.LOCAL_PUBLIC_SUFFIXES:
            return False

        # Disallow _acme-challenge.dedyn.io and the like. Rejects reserved direct children of public suffixes.
        reserved_prefixes = ('_', 'autoconfig.', 'autodiscover.',)
        if private_generation == 1 and any(self.name.startswith(prefix) for prefix in reserved_prefixes):
            return False

        # Domains covered by another user's zone can't be registered
        if self.is_covered_by_foreign_zone():
            return False

        # Domains that would cover another user's zone can't be registered
        if self.covers_foreign_zone():
            return False

        return True

    @property
    def keys(self):
        if not self._keys:
            self._keys = pdns.get_keys(self)
        return self._keys

    @property
    def touched(self):
        try:
            rrset_touched = max(updated for updated in self.rrset_set.values_list('touched', flat=True))
            # If the domain has not been published yet, self.published is None and max() would fail
            return rrset_touched if not self.published else max(rrset_touched, self.published)
        except ValueError:
            # This can be none if the domain was never published and has no records (but there should be at least NS)
            return self.published

    @property
    def is_locally_registrable(self):
        return self.parent_domain_name in settings.LOCAL_PUBLIC_SUFFIXES

    @property
    def _owner_or_none(self):
        try:
            return self.owner
        except Domain.owner.RelatedObjectDoesNotExist:
            return None

    @property
    def parent_domain_name(self):
        return self._partitioned_name[1]

    @property
    def _partitioned_name(self):
        subname, _, parent_name = self.name.partition('.')
        return subname, parent_name or None

    def save(self, *args, **kwargs):
        self.full_clean(validate_unique=False)
        super().save(*args, **kwargs)

    def update_delegation(self, child_domain: Domain):
        child_subname, child_domain_name = child_domain._partitioned_name
        if self.name != child_domain_name:
            raise ValueError('Cannot update delegation of %s as it is not an immediate child domain of %s.' %
                             (child_domain.name, self.name))

        if child_domain.pk:
            # Domain real: set delegation
            child_keys = child_domain.keys
            if not child_keys:
                raise APIException('Cannot delegate %s, as it currently has no keys.' % child_domain.name)

            RRset.objects.create(domain=self, subname=child_subname, type='NS', ttl=3600, contents=settings.DEFAULT_NS)
            RRset.objects.create(domain=self, subname=child_subname, type='DS', ttl=300,
                                 contents=[ds for k in child_keys for ds in k['ds']])
            metrics.get('desecapi_autodelegation_created').inc()
        else:
            # Domain not real: remove delegation
            for rrset in self.rrset_set.filter(subname=child_subname, type__in=['NS', 'DS']):
                rrset.delete()
            metrics.get('desecapi_autodelegation_deleted').inc()

    def delete(self):
        ret = super().delete()
        logger.warning(f'Domain {self.name} deleted (owner: {self.owner.pk})')
        return ret

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('created',)


class Token(ExportModelOperationsMixin('Token'), rest_framework.authtoken.models.Token):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key = models.CharField("Key", max_length=128, db_index=True, unique=True)
    user = models.ForeignKey(
        User, related_name='auth_tokens',
        on_delete=models.CASCADE, verbose_name="User"
    )
    name = models.CharField('Name', blank=True, max_length=64)
    last_used = models.DateTimeField(null=True, blank=True)
    plain = None

    def generate_key(self):
        self.plain = secrets.token_urlsafe(21)
        self.key = Token.make_hash(self.plain)
        return self.key

    @staticmethod
    def make_hash(plain):
        return make_password(plain, salt='static', hasher='pbkdf2_sha256_iter1')


class Donation(ExportModelOperationsMixin('Donation'), models.Model):
    @staticmethod
    def _created_default():
        return timezone.now()

    @staticmethod
    def _due_default():
        return timezone.now() + timedelta(days=7)

    @staticmethod
    def _mref_default():
        return "ONDON" + str(time.time())

    created = models.DateTimeField(default=_created_default.__func__)
    name = models.CharField(max_length=255)
    iban = models.CharField(max_length=34)
    bic = models.CharField(max_length=11, blank=True)
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    message = models.CharField(max_length=255, blank=True)
    due = models.DateTimeField(default=_due_default.__func__)
    mref = models.CharField(max_length=32, default=_mref_default.__func__)
    email = models.EmailField(max_length=255, blank=True)

    class Meta:
        managed = False


# RR set types: the good, the bad, and the ugly
# known, but unsupported types
RR_SET_TYPES_UNSUPPORTED = {
    'ALIAS',  # Requires signing at the frontend, hence unsupported in desec-stack
    'DNAME',  # "do not combine with DNSSEC", https://doc.powerdns.com/authoritative/settings.html#dname-processing
    'IPSECKEY',  # broken in pdns, https://github.com/PowerDNS/pdns/issues/9055 TODO enable support
    'KEY',  # Application use restricted by RFC 3445, DNSSEC use replaced by DNSKEY and handled automatically
    'WKS',  # General usage not recommended, "SHOULD NOT" be used in SMTP (RFC 1123)
}
# restricted types are managed in use by the API, and cannot directly be modified by the API client
RR_SET_TYPES_AUTOMATIC = {
    # corresponding functionality is automatically managed:
    'CDNSKEY', 'CDS', 'DNSKEY', 'KEY', 'NSEC', 'NSEC3', 'OPT', 'RRSIG',
    # automatically managed by the API:
    'NSEC3PARAM', 'SOA'
}
# backend types are types that are the types supported by the backend(s)
RR_SET_TYPES_BACKEND = pdns.SUPPORTED_RRSET_TYPES
# validation types are types supported by the validation backend, currently: dnspython
RR_SET_TYPES_VALIDATION = set(ANY.__all__) | set(IN.__all__)
# manageable types are directly managed by the API client
RR_SET_TYPES_MANAGEABLE = \
        (RR_SET_TYPES_BACKEND & RR_SET_TYPES_VALIDATION) - RR_SET_TYPES_UNSUPPORTED - RR_SET_TYPES_AUTOMATIC


class RRsetManager(Manager):
    def create(self, contents=None, **kwargs):
        rrset = super().create(**kwargs)
        for content in contents or []:
            RR.objects.create(rrset=rrset, content=content)
        return rrset


class RRset(ExportModelOperationsMixin('RRset'), models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True)
    touched = models.DateTimeField(auto_now=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    subname = models.CharField(
        max_length=178,
        blank=True,
        validators=[
            validate_lower,
            RegexValidator(
                regex=r'^([*]|(([*][.])?([a-z0-9_-]+[.])*[a-z0-9_-]+))$',
                message='Subname can only use (lowercase) a-z, 0-9, ., -, and _, '
                        'may start with a \'*.\', or just be \'*\'.',
                code='invalid_subname'
            )
        ]
    )
    type = models.CharField(
        max_length=10,
        validators=[
            validate_upper,
            RegexValidator(
                regex=r'^[A-Z][A-Z0-9]*$',
                message='Type must be uppercase alphanumeric and start with a letter.',
                code='invalid_type'
            )
        ]
    )
    ttl = models.PositiveIntegerField()

    objects = RRsetManager()

    class Meta:
        constraints = [
            ExclusionConstraint(
                name='cname_exclusivity',
                expressions=[
                    ('domain', RangeOperators.EQUAL),
                    ('subname', RangeOperators.EQUAL),
                    (RawSQL("int4(type = 'CNAME')", ()), RangeOperators.NOT_EQUAL),
                ],
            ),
        ]
        unique_together = (("domain", "subname", "type"),)

    @staticmethod
    def construct_name(subname, domain_name):
        return '.'.join(filter(None, [subname, domain_name])) + '.'

    @property
    def name(self):
        return self.construct_name(self.subname, self.domain.name)

    def save(self, *args, **kwargs):
        self.full_clean(validate_unique=False)
        super().save(*args, **kwargs)

    def clean_records(self, records_presentation_format):
        """
        Validates the records belonging to this set. Validation rules follow the DNS specification; some types may
        incur additional validation rules.

        Raises ValidationError if violation of DNS specification is found.

        Returns a set of records in canonical presentation format.

        :param records_presentation_format: iterable of records in presentation format
        """
        rdtype = rdatatype.from_text(self.type)
        errors = []

        if self.type == 'CNAME':
            if self.subname == '':
                errors.append('CNAME RRset cannot have empty subname.')
            if len(records_presentation_format) > 1:
                errors.append('RRset of type CNAME cannot have multiple records.')

        def _error_msg(record, detail):
            return f'Record content of {self.type} {self.name} invalid: \'{record}\': {detail}'

        records_canonical_format = set()
        for r in records_presentation_format:
            try:
                r_canonical_format = RR.canonical_presentation_format(r, rdtype)
            except binascii.Error:
                # e.g., odd-length string
                errors.append(_error_msg(r, 'Cannot parse hexadecimal or base64 record contents'))
            except dns.exception.SyntaxError as e:
                # e.g., A/127.0.0.999
                if 'quote' in e.args[0]:
                    errors.append(_error_msg(r, f'Data for {self.type} records must be given using quotation marks.'))
                else:
                    errors.append(_error_msg(r, f'Record content malformed: {",".join(e.args)}'))
            except dns.name.NeedAbsoluteNameOrOrigin:
                errors.append(_error_msg(r, 'Hostname must be fully qualified (i.e., end in a dot: "example.com.")'))
            except ValueError:
                # e.g., string ("asdf") cannot be parsed into int on base 10
                errors.append(_error_msg(r, 'Cannot parse record contents'))
            except Exception as e:
                # TODO see what exceptions raise here for faulty input
                raise e
            else:
                if r_canonical_format in records_canonical_format:
                    errors.append(_error_msg(r, f'Duplicate record content: this is identical to '
                                                f'\'{r_canonical_format}\''))
                else:
                    records_canonical_format.add(r_canonical_format)

        if any(errors):
            raise ValidationError(errors)

        return records_canonical_format

    def save_records(self, records):
        """
        Updates this RR set's resource records, discarding any old values.

        Records are expected in presentation format and are converted to canonical
        presentation format (e.g., 127.00.0.1 will be converted to 127.0.0.1).
        Raises if a invalid set of records is provided.

        This method triggers the following database queries:
        - one DELETE query
        - one SELECT query for comparison of old with new records
        - one INSERT query, if one or more records were added

        Changes are saved to the database immediately.

        :param records: list of records in presentation format
        """
        new_records = self.clean_records(records)

        # Delete RRs that are not in the new record list from the DB
        self.records.exclude(content__in=new_records).delete()  # one DELETE

        # Retrieve all remaining RRs from the DB
        unchanged_records = set(r.content for r in self.records.all())  # one SELECT

        # Save missing RRs from the new record list to the DB
        added_records = new_records - unchanged_records
        rrs = [RR(rrset=self, content=content) for content in added_records]
        RR.objects.bulk_create(rrs)  # One INSERT

    def __str__(self):
        return '<RRSet %s domain=%s type=%s subname=%s>' % (self.pk, self.domain.name, self.type, self.subname)


class RRManager(Manager):
    def bulk_create(self, rrs, **kwargs):
        ret = super().bulk_create(rrs, **kwargs)

        # For each rrset, save once to set RRset.updated timestamp and trigger signal for post-save processing
        rrsets = {rr.rrset for rr in rrs}
        for rrset in rrsets:
            rrset.save()

        return ret


class RR(ExportModelOperationsMixin('RR'), models.Model):
    created = models.DateTimeField(auto_now_add=True)
    rrset = models.ForeignKey(RRset, on_delete=models.CASCADE, related_name='records')
    content = models.TextField()

    objects = RRManager()

    @staticmethod
    def canonical_presentation_format(any_presentation_format, type_):
        """
        Converts any valid presentation format for a RR into it's canonical presentation format.
        Raises if provided presentation format is invalid.
        """
        if type_ in (dns.rdatatype.TXT, dns.rdatatype.SPF):
            # for TXT record, we slightly deviate from RFC 1035 and allow tokens that are longer than 255 byte.
            cls = LongQuotedTXT
        elif type_ == dns.rdatatype.OPENPGPKEY:
            cls = OPENPGPKEY
        else:
            # For all other record types, let dnspython decide
            cls = rdata

        wire = cls.from_text(
            rdclass=rdataclass.IN,
            rdtype=type_,
            tok=dns.tokenizer.Tokenizer(any_presentation_format),
            relativize=False
        ).to_digestable()

        # The pdns lmdb backend used on our frontends does not only store the record contents itself, but other metadata
        # (such as type etc.) Both together have to fit into the lmdb backend's current total limit of 512 bytes per RR.
        # I found the additional data to be 12 bytes (by trial and error). I believe these are the 12 bytes mentioned
        # here: https://lists.isc.org/pipermail/bind-users/2008-April/070137.html So we can use 500 bytes for the actual
        # content stored in wire format.
        # This check can be relaxed as soon as lmdb supports larger records,
        # cf. https://github.com/desec-io/desec-slave/issues/34 and https://github.com/PowerDNS/pdns/issues/8012
        if len(wire) > 500:
            raise ValidationError(f'Ensure this value has no more than 500 byte in wire format (it has {len(wire)}).')

        parser = dns.wire.Parser(wire, current=0)
        with parser.restrict_to(len(wire)):
            return cls.from_wire_parser(
                rdclass=rdataclass.IN,
                rdtype=type_,
                parser=parser,
            ).to_text()

    def __str__(self):
        return '<RR %s %s rr_set=%s>' % (self.pk, self.content, self.rrset.pk)


class AuthenticatedAction(models.Model):
    """
    Represents a procedure call on a defined set of arguments.

    Subclasses can define additional arguments by adding Django model fields and must define the action to be taken by
    implementing the `_act` method.

    AuthenticatedAction provides the `state` property which by default is a hash of the action type (defined by the
    action's class path). Other information such as user state can be included in the state hash by (carefully)
    overriding the `_state_fields` property. Instantiation of the model, if given a `state` kwarg, will raise an error
    if the given state argument does not match the state computed from `_state_fields` at the moment of instantiation.
    The same applies to the `act` method: If called on an object that was instantiated without a `state` kwargs, an
    error will be raised.

    This effectively allows hash-authenticated procedure calls by third parties as long as the server-side state is
    unaltered, according to the following protocol:

    (1) Instantiate the AuthenticatedAction subclass representing the action to be taken (no `state` kwarg here),
    (2) provide information on how to instantiate the instance, and the state hash, to a third party,
    (3) when provided with data that allows instantiation and a valid state hash, take the defined action, possibly with
        additional parameters chosen by the third party that do not belong to the verified state.
    """
    _validated = False

    class Meta:
        managed = False

    def __init__(self, *args, **kwargs):
        state = kwargs.pop('state', None)
        super().__init__(*args, **kwargs)

        if state is not None:
            self._validated = self.validate_state(state)
            if not self._validated:
                raise ValueError

    @property
    def _state_fields(self):
        """
        Returns a list that defines the state of this action (used for authentication of this action).

        Return value must be JSON-serializable.

        Values not included in the return value will not be used for authentication, i.e. those values can be varied
        freely and function as unauthenticated action input parameters.

        Use caution when overriding this method. You will usually want to append a value to the list returned by the
        parent. Overriding the behavior altogether could result in reducing the state to fewer variables, resulting
        in valid signatures when they were intended to be invalid. The suggested method for overriding is

            @property
            def _state_fields:
                return super()._state_fields + [self.important_value, self.another_added_value]

        :return: List of values to be signed.
        """
        name = '.'.join([self.__module__, self.__class__.__qualname__])
        return [name]

    @property
    def state(self):
        state = json.dumps(self._state_fields).encode()
        hash = sha256()
        hash.update(state)
        return hash.hexdigest()

    def validate_state(self, value):
        return value == self.state

    def _act(self):
        """
        Conduct the action represented by this class.
        :return: None
        """
        raise NotImplementedError

    def act(self):
        if not self._validated:
            raise RuntimeError('Action state could not be verified.')
        return self._act()


class AuthenticatedBasicUserAction(AuthenticatedAction):
    """
    Abstract AuthenticatedAction involving a user instance.
    """
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING)

    class Meta:
        managed = False

    @property
    def _state_fields(self):
        return super()._state_fields + [str(self.user.id)]


class AuthenticatedUserAction(AuthenticatedBasicUserAction):
    """
    Abstract AuthenticatedBasicUserAction, incorporating the user's id, email, password, and is_active flag into the
    Message Authentication Code state.
    """

    class Meta:
        managed = False

    @property
    def _state_fields(self):
        # TODO consider adding a "last change" attribute of the user to the state to avoid code
        #  re-use after the the state has been changed and changed back.
        return super()._state_fields + [self.user.email, self.user.password, self.user.is_active]


class AuthenticatedActivateUserAction(AuthenticatedUserAction):
    domain = models.CharField(max_length=191)

    class Meta:
        managed = False

    @property
    def _state_fields(self):
        return super()._state_fields + [self.domain]

    def _act(self):
        self.user.activate()


class AuthenticatedChangeEmailUserAction(AuthenticatedUserAction):
    new_email = models.EmailField()

    class Meta:
        managed = False

    @property
    def _state_fields(self):
        return super()._state_fields + [self.new_email]

    def _act(self):
        self.user.change_email(self.new_email)


class AuthenticatedResetPasswordUserAction(AuthenticatedUserAction):
    new_password = models.CharField(max_length=128)

    class Meta:
        managed = False

    def _act(self):
        self.user.change_password(self.new_password)


class AuthenticatedDeleteUserAction(AuthenticatedUserAction):

    class Meta:
        managed = False

    def _act(self):
        self.user.delete()


class AuthenticatedDomainBasicUserAction(AuthenticatedBasicUserAction):
    """
    Abstract AuthenticatedUserAction involving an domain instance, incorporating the domain's id, name as well as the
    owner ID into the Message Authentication Code state.
    """
    domain = models.ForeignKey(Domain, on_delete=models.DO_NOTHING)

    class Meta:
        managed = False

    @property
    def _state_fields(self):
        return super()._state_fields + [
            str(self.domain.id),  # ensures the domain object is identical
            self.domain.name,  # exclude renamed domains
            str(self.domain.owner.id),  # exclude transferred domains
        ]


class AuthenticatedRenewDomainBasicUserAction(AuthenticatedDomainBasicUserAction):

    class Meta:
        managed = False

    @property
    def _state_fields(self):
        return super()._state_fields + [str(self.domain.renewal_changed)]

    def _act(self):
        self.domain.renewal_state = Domain.RenewalState.FRESH
        self.domain.renewal_changed = timezone.now()
        self.domain.save(update_fields=['renewal_state', 'renewal_changed'])


def captcha_default_content():
    alphabet = (string.ascii_uppercase + string.digits).translate({ord(c): None for c in 'IO0'})
    content = ''.join([secrets.choice(alphabet) for _ in range(5)])
    metrics.get('desecapi_captcha_content_created').inc()
    return content


class Captcha(ExportModelOperationsMixin('Captcha'), models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True)
    content = models.CharField(
        max_length=24,
        default=captcha_default_content,
    )

    def verify(self, solution: str):
        age = timezone.now() - self.created
        self.delete()
        return (
            str(solution).upper().strip() == self.content  # solution correct
            and
            age <= settings.CAPTCHA_VALIDITY_PERIOD  # not expired
        )
