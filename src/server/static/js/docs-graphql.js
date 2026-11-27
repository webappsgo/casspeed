(function () {
  'use strict';

  var mount = document.getElementById('graphiql');
  if (!mount || !window.React || !window.ReactDOM || !window.GraphiQL) {
    return;
  }

  var endpoint = new URL(mount.dataset.endpoint || '/api/v1/server/graphql', window.location.origin);
  var fetcher = function (params) {
    return fetch(endpoint.href, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(params)
    }).then(function (response) {
      return response.json();
    });
  };

  var app = React.createElement(GraphiQL, { fetcher: fetcher });
  ReactDOM.createRoot(mount).render(app);
})();
