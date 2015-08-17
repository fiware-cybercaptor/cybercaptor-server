var hooks = require('hooks');
var stash = {};

// hook to retrieve session after initialize call
hooks.after('REST API after init > Initialize > Initialize from XML topology', function (transaction) {
    stash['cookie'] = transaction.real.headers['set-cookie'];
});

// hook to set the session cookie in all following requests
hooks.beforeEach(function (transaction) {
    if (stash['cookie'] != undefined) {
        transaction.request['headers']['Cookie'] = stash['cookie'];
    }
});
