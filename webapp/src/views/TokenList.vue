<script>
import CrudList from './CrudList';
import store from '../store';

export default {
  name: 'CrudTokenList',
  extends: CrudList,
  data() {
    return {
        createable: true,
        updatable: true,
        destroyable: true,
        headlines: {
          table: 'Tokens',
          create: 'Generate New Token',
          destroy: 'Delete Token',
        },
        texts: {
          banner: () => ('<strong>New feature:</strong> You can now configure your tokens for finer access control. Check out the new settings below!'),
          create: () => ('<p>You can create a new API token here. The token is displayed after submitting this form.</p><p><strong>Warning:</strong> Be sure to protect your tokens appropriately! Knowledge of an API token allows performing actions on your behalf.</p>'),
          createSuccess: (item) => `Your new token is: <code>${item.token}</code><br />It is only displayed once.`,
          destroy: d => (d.name ? `Delete token with name "${d.name}" and ID ${d.id}?` : `Delete unnamed token with ID ${d.id}?`),
          destroyInfo: () => ('This operation is permanent. Any devices using this token will no longer be able to authenticate.'),
          destroyWarning: d => (d.id == store.state.token.id ? 'This is your current session token. Deleting it will invalidate the session.' : ''),
        },
        columns: {
          id: {
            name: 'item.id',
            text: 'Identifier',
            align: 'left',
            value: 'id',
            readonly: true,
            datatype: 'GenericText',
            searchable: true,
          },
          name: {
            name: 'item.name',
            text: 'Name',
            textCreate: 'Token name (for your convenience only)',
            align: 'left',
            sortable: true,
            value: 'name',
            readonly: false,
            writeOnCreate: true,
            datatype: 'GenericText',
            searchable: true,
          },
          perm_manage_tokens: {
            name: 'item.perm_manage_tokens',
            text: 'Can manage tokens',
            textCreate: 'Can manage tokens?',
            align: 'left',
            sortable: true,
            value: 'perm_manage_tokens',
            readonly: false,
            writeOnCreate: true,
            datatype: 'SwitchBox',
            searchable: false,
          },
          created: {
            name: 'item.created',
            text: 'Created',
            align: 'left',
            sortable: true,
            value: 'created',
            readonly: true,
            datatype: 'TimeAgo',
            searchable: false,
          },
          last_used: {
            name: 'item.last_used',
            text: 'Last used',
            align: 'left',
            sortable: true,
            value: 'last_used',
            readonly: true,
            datatype: 'TimeAgo',
            searchable: false,
          },
        },
        paths: {
          list: 'auth/tokens/',
          create: 'auth/tokens/',
          delete: 'auth/tokens/:{id}/',
          update: 'auth/tokens/:{id}/',
        },
        itemDefaults: () => ({ name: '' }),
        itemIsReadOnly: (item) => item.id == store.state.token.id,
        postcreate: () => false,  // do not close dialog
    }
  },
};
</script>
