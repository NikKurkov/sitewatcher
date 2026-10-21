"""Bound page downloads before decompression can allocate an unbounded body."""
from __future__ import annotations

import zlib

import httpx

DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class BodyReadError(httpx.RequestError):
    """A page body cannot be inspected completely within the resource policy."""

    def __init__(self, message: str, response: httpx.Response):
        super().__init__(message, request=response.request)
        self.status_code = response.status_code


async def _read_body(
    response: httpx.Response, wire_limit: int, decoded_limit: int,
) -> tuple[bytes, int]:
    encoding = response.headers.get('content-encoding', 'identity').strip().lower()
    if encoding not in {'identity', 'gzip', 'deflate'}:
        raise BodyReadError('unsupported body encoding', response)
    # Mock/custom transports may return a body that is already decoded and read.
    if response.is_stream_consumed:
        body = response.content
        wire_size = response.num_bytes_downloaded or len(body)
        if wire_size > wire_limit or len(body) > decoded_limit:
            raise BodyReadError('body exceeds configured byte limit', response)
        return body, wire_size

    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == 'gzip' else None
    body = bytearray()
    prefix = b''
    wire_size = 0
    try:
        async for raw in response.aiter_raw():
            wire_size += len(raw)
            if wire_size > wire_limit:
                raise BodyReadError('body exceeds configured wire byte limit', response)
            if encoding == 'deflate' and decoder is None:
                prefix += raw
                if len(prefix) < 2:
                    continue
                # HTTP deflate normally has a zlib header; tolerate raw deflate.
                zlib_header = prefix[0] & 15 == 8 and int.from_bytes(prefix[:2]) % 31 == 0
                decoder = zlib.decompressobj(zlib.MAX_WBITS if zlib_header else -zlib.MAX_WBITS)
                raw, prefix = prefix, b''
            decoded = decoder.decompress(raw, decoded_limit - len(body) + 1) if decoder else raw
            if len(body) + len(decoded) > decoded_limit:
                raise BodyReadError('body exceeds configured decoded byte limit', response)
            body.extend(decoded)
            if decoder is not None and decoder.unused_data:
                raise BodyReadError('body has trailing or concatenated compressed data', response)
    except httpx.RemoteProtocolError as error:
        raise BodyReadError('incomplete HTTP body', response) from error
    except zlib.error as error:
        raise BodyReadError('invalid compressed body', response) from error
    # Do not call unbounded zlib.flush(): a complete stream has already emitted
    # all output through max_length-limited decompress calls.
    if encoding != 'identity' and (decoder is None or not decoder.eof):
        raise BodyReadError('incomplete compressed body', response)
    return bytes(body), wire_size


async def bounded_get(
    client: httpx.AsyncClient, url: str, *, max_response_bytes: int,
    follow_redirects: bool, prior_body_bytes: tuple[int, int] = (0, 0), **kwargs,
) -> httpx.Response:
    """Read a GET chain with cumulative wire/decoded limits and native redirects.

    HTTPX's automatic redirects and aiter_bytes both read/decode without limits,
    so use its public next_request and raw stream APIs instead. Unsupported or
    incomplete encodings fail visibly; they are not retried as transport errors.
    """
    if max_response_bytes <= 0:
        raise ValueError('max_response_bytes must be positive')
    headers = httpx.Headers(kwargs.pop('headers', None))
    headers['Accept-Encoding'] = 'gzip, deflate'
    request = client.build_request('GET', url, headers=headers, **kwargs)
    history = []
    wire_remaining = max_response_bytes - prior_body_bytes[0]
    decoded_remaining = max_response_bytes - prior_body_bytes[1]
    while True:
        if len(history) > client.max_redirects:
            raise httpx.TooManyRedirects('Exceeded maximum allowed redirects.', request=request)
        response = await client.send(request, stream=True, follow_redirects=False)
        try:
            body, wire_size = await _read_body(response, wire_remaining, decoded_remaining)
            wire_remaining -= wire_size
            decoded_remaining -= len(body)
            next_request = response.next_request if follow_redirects else None
            # The replacement contains decoded bytes, so encoding/length headers
            # must describe this representation rather than compressed wire data.
            result_headers = response.headers.copy()
            for name in ('content-encoding', 'content-length'):
                result_headers.pop(name, None)
            result = httpx.Response(
                response.status_code, headers=result_headers,
                content=body if next_request is None else b'', request=response.request,
                history=history,
                extensions={
                    **response.extensions,
                    "body_bytes": (max_response_bytes - wire_remaining,
                                   max_response_bytes - decoded_remaining),
                },
            )
        finally:
            await response.aclose()
        if next_request is None:
            return result
        history.append(result)
        request = next_request
