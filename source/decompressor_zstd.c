#include "bsdiff.h"
#include "bsdiff_private.h"
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

struct zstd_decompressor
{
	int initialized;
	struct bsdiff_stream *strm;
	ZSTD_DStream *z_strm;
	ZSTD_inBuffer in;
	ZSTD_outBuffer out;
	int input_eof;
	size_t zerr;
	size_t buf_size;
	char buf[];
};

static int zstd_decompressor_init(void *state, struct bsdiff_stream *stream)
{
	struct zstd_decompressor *dec = (struct zstd_decompressor*)state;

	if (dec->initialized)
		return BSDIFF_ERROR;

	dec->strm = stream;

	dec->z_strm = ZSTD_createDStream();

	dec->zerr = 0;

	dec->in.pos = 0;
	dec->in.size = 0;
	dec->in.src = NULL;

	dec->input_eof = 0;

	dec->out.pos = 0;
	dec->out.size = 0;
	dec->out.dst = NULL;

	dec->initialized = 1;

	return BSDIFF_SUCCESS;
}

static int zstd_decompressor_read(void *state, void *buffer, size_t size, size_t *readed)
{
	struct zstd_decompressor *dec = (struct zstd_decompressor*)state;
	int ret;
	size_t cb;

	*readed = 0;

	if (!dec->initialized)
		return BSDIFF_ERROR;
	if (dec->zerr == 0 && dec->input_eof)
		return BSDIFF_END_OF_FILE;
	if (size >= UINT32_MAX)
		return BSDIFF_INVALID_ARG;
	if (size == 0)
		return BSDIFF_SUCCESS;

	dec->out.size = size;
	dec->out.dst = (void*)buffer;
	dec->out.pos = 0;

	while (1) {
		/* check if more input needed */
		if (!dec->input_eof && dec->in.pos == dec->in.size) {
			ret = dec->strm->read(dec->strm->state, dec->buf, dec->buf_size, &cb);
			if ((ret != BSDIFF_SUCCESS && ret != BSDIFF_END_OF_FILE) || (cb == 0))
				return BSDIFF_ERROR;
			if (ret == BSDIFF_END_OF_FILE) {
				dec->input_eof = 1;
			}
			dec->in.src = dec->buf;
			dec->in.size = cb;
			dec->in.pos = 0;
		}

		size_t old_out_pos = dec->out.pos;
		/* decompress some amount of data */
		dec->zerr = ZSTD_decompressStream(dec->z_strm, &dec->out, &dec->in);
		if (ZSTD_isError(dec->zerr))
			return BSDIFF_ERROR;

		/* update readed */
		*readed += dec->out.pos - old_out_pos;

		/* the end of compressed stream was detected */
		if (dec->zerr == 0 && dec->input_eof)
			return BSDIFF_END_OF_FILE;

		/* return if no more output buffer available */
		if (dec->out.pos == dec->out.size)
			return BSDIFF_SUCCESS;
	}

	/* never reached */
	return BSDIFF_ERROR;
}

static void zstd_decompressor_close(void *state)
{
	struct zstd_decompressor *dec = (struct zstd_decompressor*)state;

	if (dec->initialized) {
		/* cleanup BZ2 decompress state */
		ZSTD_freeDStream(dec->z_strm);
	}

	/* free the state */
	free(dec);
}

int bsdiff_create_zstd_decompressor(
	struct bsdiff_decompressor *dec)
{
	struct zstd_decompressor *state;

	size_t buf_size = ZSTD_DStreamInSize();

	state = malloc(sizeof(struct zstd_decompressor) + buf_size);
	if (!state)
		return BSDIFF_OUT_OF_MEMORY;
	
	state->initialized = 0;
	state->strm = NULL;

	state->buf_size = buf_size;

	memset(dec, 0, sizeof(*dec));
	dec->state = state;
	dec->init = zstd_decompressor_init;
	dec->read = zstd_decompressor_read;
	dec->close = zstd_decompressor_close;

	return BSDIFF_SUCCESS;
}
