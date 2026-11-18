"""Content negotiation for the plain-text job log routes (Core 1.18.5).

The UI asks for a log with ``Accept: text/plain``. Tactical's DRF settings only offer the JSON renderer, so DRF would answer
406 "Could not satisfy the request Accept header" before the view runs. These views return an HttpResponse for the log and a JSON
body for errors, so the renderer choice does not matter. This mixin picks the first renderer and never refuses.
Authentication and permission checks still run after negotiation, exactly as before.
"""


class LogNegotiationMixin:
    def perform_content_negotiation(self, request, force=False):
        renderer = self.get_renderers()[0]
        return renderer, renderer.media_type
