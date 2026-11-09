// Viewer request on the site's default behaviour: `/dir/` serves `dir/index.html`, and a path whose last
// segment has no dot redirects to the same path with a trailing slash, so relative links resolve.
function handler(event) {
  var request = event.request;
  var uri = request.uri;
  if (uri.endsWith("/")) {
    request.uri = uri + "index.html";
    return request;
  }
  if (uri.split("/").pop().indexOf(".") === -1) {
    var qs = Object.keys(request.querystring)
      .map(function (k) {
        var v = request.querystring[k];
        return v.value === "" ? k : k + "=" + v.value;
      })
      .join("&");
    return {
      statusCode: 301,
      statusDescription: "Moved Permanently",
      headers: { location: { value: uri + "/" + (qs ? "?" + qs : "") } },
    };
  }
  return request;
}
