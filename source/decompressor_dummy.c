#include "bsdiff.h"
#include "bsdiff_private.h"
#include <stdlib.h>
#include <string.h>

struct dummy_decompressor
{
	struct bsdiff_stream *strm;
};

static int dummy_decompressor_init(void *state, struct bsdiff_stream *stream)
{
	struct dummy_decompressor *dec = (struct dummy_decompressor*)state;

	if (dec->strm)
		return BSDIFF_ERROR;

	dec->strm = stream;

	return BSDIFF_SUCCESS;
}

static int dummy_decompressor_read(void *state, void *buffer, size_t size, size_t *readed)
{
	struct dummy_decompressor *dec = (struct dummy_decompressor*)state;

	return dec->strm->read(dec->strm, buffer, size, readed);
}

static void dummy_decompressor_close(void *state)
{
	struct dummy_decompressor *dec = (struct dummy_decompressor*)state;
	/* free the state */
	free(dec);
}

int bsdiff_create_dummy_decompressor(
	struct bsdiff_decompressor *dec)
{
	struct dummy_decompressor *state;


	state = malloc(sizeof(struct dummy_decompressor));
	if (!state)
		return BSDIFF_OUT_OF_MEMORY;
	
	state->strm = NULL;

	memset(dec, 0, sizeof(*dec));
	dec->state = state;
	dec->init = dummy_decompressor_init;
	dec->read = dummy_decompressor_read;
	dec->close = dummy_decompressor_close;

	return BSDIFF_SUCCESS;
}
