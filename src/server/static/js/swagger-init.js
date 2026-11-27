/* Initialize the locally hosted Swagger UI bundle. */
(function () {
  'use strict';

  var container = document.getElementById('swagger-ui');
  if (!container || !window.SwaggerUIBundle || !window.SwaggerUIStandalonePreset) {
    return;
  }

  window.SwaggerUIBundle({
    url: container.dataset.specUrl,
    dom_id: '#swagger-ui',
    deepLinking: true,
    presets: [window.SwaggerUIBundle.presets.apis, window.SwaggerUIStandalonePreset],
    layout: 'StandaloneLayout',
    persistAuthorization: false
  });
}());
