var hooks = require('hooks');
var stash = {};

// hook to retrieve session after initialize call
hooks.after('REST API after initialization > Initialize > Initialize from XML topology', function (transaction) {
    stash['cookie'] = transaction.real.headers['set-cookie'];
});

// hook to set the session cookie in all following requests
hooks.beforeEach(function (transaction) {
    if (stash['cookie'] != undefined) {
        transaction.request['headers']['Cookie'] = stash['cookie'];
    }
    //Delete all spaces in XML in expected body
    if (transaction.expected.headers['Content-Type'] === 'application/xml') {
        transaction.expected.body = transaction.expected.body.replace(/\s/g, '');
    }

});

//Delete all spaces in XML in real body
hooks.beforeEachValidation(function (transaction) {
    if (transaction.real.headers['Content-Type'] === 'application/xml' || transaction.real.headers['content-type'] === 'application/xml') {
        transaction.real.body = transaction.real.body.replace(/\s/g, '');
    }

});