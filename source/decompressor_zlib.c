#include "bsdiff.h"
#include "bsdiff_private.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

struct zlib_decompressor
{
	int initialized;
	struct bsdiff_stream *strm;
	z_stream z_strm;
	int zerr;
	char buf[5000];
};

static int zlib_decompressor_init(void *state, struct bsdiff_stream *stream)
{
	struct zlib_decompressor *dec = (struct zlib_decompressor*)state;

	if (dec->initialized)
		return BSDIFF_ERROR;

	dec->strm = stream;

	dec->z_strm.zalloc = NULL;
	dec->z_strm.zfree = NULL;
	dec->z_strm.opaque = NULL;
	if (inflateInit(&(dec->z_strm)) != Z_OK)
		return BSDIFF_ERROR;
	dec->z_strm.avail_in = 0;
	dec->z_strm.next_in = NULL;
	dec->z_strm.avail_out = 0;
	dec->z_strm.next_out = NULL;
	
	dec->zerr = Z_OK;

	dec->initialized = 1;

	return BSDIFF_SUCCESS;
}

static int zlib_decompressor_read(void *state, void *buffer, size_t size, size_t *readed)
{
	struct zlib_decompressor *dec = (struct zlib_decompressor*)state;
	int ret;
	size_t cb;
	unsigned int old_avail_out;

	*readed = 0;

	if (!dec->initialized)
		return BSDIFF_ERROR;
	if (dec->zerr != Z_OK)
		return (dec->zerr == Z_STREAM_END) ? BSDIFF_END_OF_FILE : BSDIFF_ERROR;
	if (size >= UINT32_MAX)
		return BSDIFF_INVALID_ARG;
	if (size == 0)
		return BSDIFF_SUCCESS;

	dec->z_strm.avail_out = (unsigned int)size;
	dec->z_strm.next_out = (Bytef*)buffer;

	while (1) {
		/* input buffer is empty */
		if (dec->z_strm.avail_in == 0) {
			ret = dec->strm->read(dec->strm->state, dec->buf, sizeof(dec->buf), &cb);
			if ((ret != BSDIFF_SUCCESS && ret != BSDIFF_END_OF_FILE) || (cb == 0))
				return BSDIFF_ERROR;
			dec->z_strm.next_in = (Bytef*)dec->buf;
			dec->z_strm.avail_in = (unsigned int)cb;
		}

		old_avail_out = dec->z_strm.avail_out;
		/* decompress some amount of data */
		dec->zerr = inflate(&(dec->z_strm), 0);
		if (dec->zerr != Z_OK && dec->zerr != Z_STREAM_END)
			return BSDIFF_ERROR;

		/* update readed */
		*readed += old_avail_out - dec->z_strm.avail_out;

		/* the end of compressed stream was detected */
		if (dec->zerr == Z_STREAM_END)
			return BSDIFF_END_OF_FILE;
		/* all output buffer has been consumed */
		if (dec->z_strm.avail_out == 0)
			return BSDIFF_SUCCESS;
	}

	/* never reached */
	return BSDIFF_ERROR;
}

static void zlib_decompressor_close(void *state)
{
	struct zlib_decompressor *dec = (struct zlib_decompressor*)state;

	if (dec->initialized) {
		/* cleanup BZ2 decompress state */
		inflateEnd(&(dec->z_strm));
	}

	/* free the state */
	free(dec);
}

int bsdiff_create_zlib_decompressor(
	struct bsdiff_decompressor *dec)
{
	struct zlib_decompressor *state;

	state = malloc(sizeof(struct zlib_decompressor));
	if (!state)
		return BSDIFF_OUT_OF_MEMORY;
	state->initialized = 0;
	state->strm = NULL;

	memset(dec, 0, sizeof(*dec));
	dec->state = state;
	dec->init = zlib_decompressor_init;
	dec->read = zlib_decompressor_read;
	dec->close = zlib_decompressor_close;

	return BSDIFF_SUCCESS;
}
