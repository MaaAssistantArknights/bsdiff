#include <assert.h>
#include <bzlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>

#include "bsdiff.h"
#include "bsdiff_private.h"

int bsdiff_create_bz2_compressor(struct bsdiff_compressor *enc);
int bsdiff_create_bz2_decompressor(struct bsdiff_decompressor *dec);

int bsdiff_create_zlib_decompressor(struct bsdiff_decompressor *dec);

int bsdiff_create_zstd_decompressor(struct bsdiff_decompressor *dec);

int bsdiff_create_dummy_decompressor(struct bsdiff_decompressor *dec);

static int64_t offtin(uint8_t *buf) {
	int64_t y;

	y = buf[7] & 0x7F;
	y = y * 256;
	y += buf[6];
	y = y * 256;
	y += buf[5];
	y = y * 256;
	y += buf[4];
	y = y * 256;
	y += buf[3];
	y = y * 256;
	y += buf[2];
	y = y * 256;
	y += buf[1];
	y = y * 256;
	y += buf[0];

	if (buf[7] & 0x80) y = -y;

	return y;
}

static void offtout(int64_t x, uint8_t *buf) {
	int64_t y;

	if (x < 0)
		y = -x;
	else
		y = x;

	buf[0] = y % 256;
	y -= buf[0];
	y = y / 256;
	buf[1] = y % 256;
	y -= buf[1];
	y = y / 256;
	buf[2] = y % 256;
	y -= buf[2];
	y = y / 256;
	buf[3] = y % 256;
	y -= buf[3];
	y = y / 256;
	buf[4] = y % 256;
	y -= buf[4];
	y = y / 256;
	buf[5] = y % 256;
	y -= buf[5];
	y = y / 256;
	buf[6] = y % 256;
	y -= buf[6];
	y = y / 256;
	buf[7] = y % 256;

	if (x < 0) buf[7] |= 0x80;
}

struct maa_patch_packer {
	struct bsdiff_stream *stream;
	int mode;

	int64_t new_size;

	int64_t header_x;
	int64_t header_y;
	int64_t header_z;

	struct bsdiff_stream cpf;
	struct bsdiff_stream dpf;
	struct bsdiff_stream epf;
	struct bsdiff_decompressor cpf_dec;
	struct bsdiff_decompressor dpf_dec;
	struct bsdiff_decompressor epf_dec;

	struct bsdiff_compressor enc;
	uint8_t *db;
	uint8_t *eb;
	int64_t dblen;
	int64_t eblen;

	int flushed;
};

static int maa_patch_packer_create_decompressor(char compression_type, struct bsdiff_decompressor *dec) {
	switch (compression_type) {
		case 'B':
			return bsdiff_create_bz2_decompressor(dec);
		case 'D':
			return bsdiff_create_zlib_decompressor(dec);
		case 'Z':
			return bsdiff_create_zstd_decompressor(dec);
		case '-':
			return bsdiff_create_dummy_decompressor(dec);
		default:
			return BSDIFF_CORRUPT_PATCH;
	}
}

static int maa_patch_packer_read_new_size(void *state, int64_t *size) {
	int ret;
	uint8_t header[32];
	size_t cb;
	int64_t bzctrllen, bzdatalen, newsize;
	int64_t read_start, read_end;
	char compression_type[3] = {0};

	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_READ);
	assert(packer->new_size == -1);

	/*
	File format:
			0		8	"BSDIFF40"
			8		8	X
			16		8	Y
			24		8	sizeof(newfile)
			32		X	bzip2(control block)
			32+X	Y	bzip2(diff block)
			32+X+Y	???	bzip2(extra block)
	with control block a set of triples (x,y,z) meaning "add x bytes
	from oldfile to x bytes from the diff block; copy y bytes from the
	extra block; seek forwards in oldfile by z bytes".
	*/

	/* Read header */
	ret = packer->stream->read(packer->stream->state, header, 32, &cb);
	if (ret != BSDIFF_SUCCESS) return BSDIFF_FILE_ERROR;

	/* Check for appropriate magic */
	if (memcmp(header, "BSDIFF40", 8) == 0) {
		compression_type[0] = 'B';
		compression_type[1] = 'B';
		compression_type[2] = 'B';
	} else if (memcmp(header, "BSDFM", 5) == 0) {
		compression_type[0] = header[5];
		compression_type[1] = header[6];
		compression_type[2] = header[7];
	} else {
		return BSDIFF_CORRUPT_PATCH;
	}

	for (int i = 0; i < 3; i++) {
		if (compression_type[i] != 'B' && compression_type[i] != 'D' && compression_type[i] != 'Z') {
			return BSDIFF_CORRUPT_PATCH;
		}
	}

	/* Read lengths from header */
	bzctrllen = offtin(header + 8);
	bzdatalen = offtin(header + 16);
	newsize = offtin(header + 24);
	if ((bzctrllen < 0) || (bzdatalen < 0) || (newsize < 0)) return BSDIFF_CORRUPT_PATCH;

	/* Open substreams and create decompressors */
	/* control block */
	read_start = 32;
	read_end = read_start + bzctrllen;
	if (bsdiff_open_substream(packer->stream, read_start, read_end, &(packer->cpf)) != BSDIFF_SUCCESS)
		return BSDIFF_FILE_ERROR;
	if (maa_patch_packer_create_decompressor(compression_type[0], &(packer->cpf_dec)) != BSDIFF_SUCCESS)
		return BSDIFF_ERROR;
	if (packer->cpf_dec.init(packer->cpf_dec.state, &(packer->cpf)) != BSDIFF_SUCCESS) return BSDIFF_ERROR;

	/* diff block */
	read_start = read_end;
	read_end = read_start + bzdatalen;
	if (bsdiff_open_substream(packer->stream, read_start, read_end, &(packer->dpf)) != BSDIFF_SUCCESS)
		return BSDIFF_FILE_ERROR;
	if (maa_patch_packer_create_decompressor(compression_type[1], &(packer->dpf_dec)) != BSDIFF_SUCCESS)
		return BSDIFF_ERROR;
	if (packer->dpf_dec.init(packer->dpf_dec.state, &(packer->dpf)) != BSDIFF_SUCCESS) return BSDIFF_ERROR;

	/* extra block */
	read_start = read_end;
	if ((packer->stream->seek(packer->stream->state, 0, BSDIFF_SEEK_END) != BSDIFF_SUCCESS) ||
	    (packer->stream->tell(packer->stream->state, &read_end) != BSDIFF_SUCCESS)) {
		return BSDIFF_FILE_ERROR;
	}
	if (bsdiff_open_substream(packer->stream, read_start, read_end, &(packer->epf)) != BSDIFF_SUCCESS)
		return BSDIFF_FILE_ERROR;
	if (maa_patch_packer_create_decompressor(compression_type[2], &(packer->epf_dec)) != BSDIFF_SUCCESS)
		return BSDIFF_ERROR;
	if (packer->epf_dec.init(packer->epf_dec.state, &(packer->epf)) != BSDIFF_SUCCESS) return BSDIFF_ERROR;

	packer->new_size = newsize;

	*size = packer->new_size;

	return BSDIFF_SUCCESS;
}

static int maa_patch_packer_read_entry_header(void *state, int64_t *diff, int64_t *extra, int64_t *seek) {
	int ret;
	uint8_t buf[24];
	size_t cb;

	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_READ);
	assert(packer->new_size >= 0);
	assert(packer->header_x == 0 && packer->header_y == 0);

	ret = packer->cpf_dec.read(packer->cpf_dec.state, buf, 24, &cb);
	if ((ret != BSDIFF_SUCCESS && ret != BSDIFF_END_OF_FILE) || (cb != 24)) return BSDIFF_ERROR;
	packer->header_x = offtin(buf);
	packer->header_y = offtin(buf + 8);
	packer->header_z = offtin(buf + 16);

	*diff = packer->header_x;
	*extra = packer->header_y;
	*seek = packer->header_z;

	return BSDIFF_SUCCESS;
}

static int maa_patch_packer_read_entry_diff(void *state, void *buffer, size_t size, size_t *readed) {
	int ret;
	int64_t cb;

	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_READ);
	assert(packer->new_size >= 0);
	assert(packer->header_x >= 0);

	*readed = 0;

	cb = (int64_t)size;
	if (packer->header_x < cb) cb = packer->header_x;
	if (cb <= 0) return BSDIFF_END_OF_FILE;

	ret = packer->dpf_dec.read(packer->dpf_dec.state, buffer, (size_t)cb, readed);
	packer->header_x -= (int64_t)(*readed);
	return ret;
}

static int maa_patch_packer_read_entry_extra(void *state, void *buffer, size_t size, size_t *readed) {
	int ret;
	int64_t cb;

	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_READ);
	assert(packer->new_size >= 0);
	assert(packer->header_y >= 0);

	*readed = 0;

	cb = (int64_t)size;
	if (packer->header_y < cb) cb = packer->header_y;
	if (cb <= 0) return BSDIFF_END_OF_FILE;

	ret = packer->epf_dec.read(packer->epf_dec.state, buffer, (size_t)cb, readed);
	packer->header_y -= (int64_t)(*readed);
	return ret;
}

static int maa_patch_packer_write_new_size(void *state, int64_t size) {
	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_WRITE);
	assert(packer->new_size == -1);
	assert(size >= 0);

	int err = bsdiff_open_memory_stream(BSDIFF_MODE_WRITE, NULL, 0, &(packer->cpf));
	if (err != BSDIFF_SUCCESS) {
		return err;
	}

	/* Allocate memory for db && eb */
	assert(packer->db == NULL && packer->dblen == 0);
	assert(packer->eb == NULL && packer->eblen == 0);
	packer->db = malloc((size_t)(size + 1));
	packer->eb = malloc((size_t)(size + 1));
	if (!packer->db || !packer->eb) return BSDIFF_OUT_OF_MEMORY;
	packer->dblen = 0;
	packer->eblen = 0;

	packer->new_size = size;

	return BSDIFF_SUCCESS;
}

static int maa_patch_packer_write_entry_header(void *state, int64_t diff, int64_t extra, int64_t seek) {
	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_WRITE);
	assert(packer->new_size >= 0);
	assert(diff >= 0);
	assert(extra >= 0);

	assert(packer->header_x == 0 && packer->header_y == 0);
	packer->header_x = diff;
	packer->header_y = extra;
	packer->header_z = seek;

	/* Write a triple */
	uint8_t buf[24] = {0};
	offtout(packer->header_x, buf);
	offtout(packer->header_y, buf + 8);
	offtout(packer->header_z, buf + 16);
	int ret = packer->cpf.write(packer->cpf.state, buf, 24);
	if (ret != BSDIFF_SUCCESS) return ret;

	return BSDIFF_SUCCESS;
}

static int maa_patch_packer_write_entry_diff(void *state, const void *buffer, size_t size) {
	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_WRITE);
	assert(packer->new_size >= 0);

	if ((int64_t)size > packer->header_x) return BSDIFF_INVALID_ARG;
	if (packer->dblen + (int64_t)size > packer->new_size) return BSDIFF_INVALID_ARG;
	memcpy(packer->db + packer->dblen, buffer, size);
	packer->dblen += (int64_t)size;
	packer->header_x -= (int64_t)size;

	return BSDIFF_SUCCESS;
}

static int maa_patch_packer_write_entry_extra(void *state, const void *buffer, size_t size) {
	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_WRITE);
	assert(packer->new_size >= 0);

	if ((int64_t)size > packer->header_y) return BSDIFF_INVALID_ARG;
	if (packer->eblen + (int64_t)size > packer->new_size) return BSDIFF_INVALID_ARG;
	memcpy(packer->eb + packer->eblen, buffer, size);
	packer->eblen += (int64_t)size;
	packer->header_y -= (int64_t)size;

	return BSDIFF_SUCCESS;
}

static int deflate_block(uint8_t *buf, size_t len, uint8_t **out, size_t *outlen) {
	if (buf == NULL || out == NULL || outlen == NULL) return BSDIFF_INVALID_ARG;
	z_stream strm = {0};
	uint8_t *outbuf = malloc(len);
	if (!outbuf) return BSDIFF_OUT_OF_MEMORY;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.next_in = buf;
	strm.avail_in = len;
	strm.avail_out = len;
	strm.next_out = outbuf;

	if (deflateInit(&strm, Z_BEST_COMPRESSION) != Z_OK) {
		free(outbuf);
		return BSDIFF_ERROR;
	}
	if (deflate(&strm, Z_FINISH) != Z_STREAM_END) {
		free(outbuf);
		deflateEnd(&strm);
		return BSDIFF_ERROR;
	}

	if (deflateEnd(&strm) != Z_OK) {
		free(outbuf);
	}

	*out = outbuf;
	*outlen = (size_t)strm.total_out;
	return BSDIFF_SUCCESS;
}

static int bzip2_block(uint8_t *buf, size_t len, uint8_t **out, size_t *outlen) {
	bz_stream strm = {0};
	uint8_t *outbuf = malloc(len);
	if (!outbuf) return BSDIFF_OUT_OF_MEMORY;

	strm.bzalloc = NULL;
	strm.bzfree = NULL;
	strm.opaque = NULL;
	strm.next_in = (char *)buf;
	strm.avail_in = len;
	strm.next_out = (char *)outbuf;
	strm.avail_out = len;

	if (BZ2_bzCompressInit(&strm, 9, 0, 0) != BZ_OK) {
		free(outbuf);
		return BSDIFF_ERROR;
	}
	if (BZ2_bzCompress(&strm, BZ_FINISH) != BZ_STREAM_END) {
		free(outbuf);
		BZ2_bzCompressEnd(&strm);
		return BSDIFF_ERROR;
	}
	if (BZ2_bzCompressEnd(&strm) != BZ_OK) {
		free(outbuf);
		return BSDIFF_ERROR;
	}

	*outlen = (size_t)(strm.total_out_lo32 | ((uint64_t)strm.total_out_hi32 << 32));
	*out = outbuf;
	return BSDIFF_SUCCESS;
}

static int zstd_block(uint8_t *buf, size_t len, uint8_t **out, size_t *outlen) {
	size_t outbuflen = ZSTD_compressBound(len);
	uint8_t *outbuf = malloc(outbuflen);
	if (!outbuf) return BSDIFF_OUT_OF_MEMORY;
	size_t compressed = ZSTD_compress(outbuf, outbuflen, buf, len, 22);
	if (ZSTD_isError(compressed)) {
		free(outbuf);
		return BSDIFF_ERROR;
	}
	*out = outbuf;
	*outlen = compressed;
	return BSDIFF_SUCCESS;
}

static int find_best_compression(uint8_t *data, size_t len, uint8_t **out, size_t *outlen, char *outtype) {
	/* No compression */
	size_t bestlen = len;
	char besttype = '-';

	uint8_t *bestbuf = NULL;

	int err = 0;
	uint8_t *alternate_buf = NULL;
	size_t alternate_len = (size_t)-1;

	/* deflate */
	err = deflate_block(data, len, &alternate_buf, &alternate_len);
	if (err == BSDIFF_SUCCESS) {
		if (alternate_len < bestlen) {
			uint8_t *swap = bestbuf;
			bestbuf = alternate_buf;
			alternate_buf = swap;

			bestlen = alternate_len;
			besttype = 'D';
		}
		if (alternate_buf) {
			free(alternate_buf);
		}
	}

	/* bzip2 */
	err = bzip2_block(data, len, &alternate_buf, &alternate_len);
	if (err == BSDIFF_SUCCESS) {
		if (alternate_len < bestlen) {
			uint8_t *swap = bestbuf;
			bestbuf = alternate_buf;
			alternate_buf = swap;

			bestlen = alternate_len;
			besttype = 'B';
		}
		if (alternate_buf) {
			free(alternate_buf);
		}
	}

	/* zstd */
	err = zstd_block(data, len, &alternate_buf, &alternate_len);
	if (err == BSDIFF_SUCCESS) {
		if (alternate_len < bestlen) {
			uint8_t *swap = bestbuf;
			bestbuf = alternate_buf;
			alternate_buf = swap;

			bestlen = alternate_len;
			besttype = 'Z';
		}
		if (alternate_buf) {
			free(alternate_buf);
		}
	}

	if (!bestbuf) {
		// no cpmpression, copy the input buffer for consistency
		bestbuf = malloc(len);
		bestlen = len;
		besttype = '-';
		if (!bestbuf) return BSDIFF_OUT_OF_MEMORY;
		memcpy(bestbuf, data, len);
	}

	*out = bestbuf;
	*outlen = bestlen;
	*outtype = besttype;
	return BSDIFF_SUCCESS;
}

static int maa_patch_packer_flush(void *state) {
	uint8_t header[32] = {0};
	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	assert(packer->mode == BSDIFF_MODE_WRITE);
	assert(packer->new_size >= 0);
	assert(packer->header_x == 0 && packer->header_y == 0);

	memcpy(header, "BSDIFF40", 8);
	offtout(packer->new_size, header + 24);

	uint8_t *uncompressed_data;
	size_t uncompressed_len;

	uint8_t *compressed_ctrl, *compressed_diff, *compressed_extra;
	size_t compressed_ctrl_len, compressed_diff_len, compressed_extra_len;
	char ctrl_type, diff_type, extra_type;

	int result = BSDIFF_SUCCESS;

	/* Flush ctrl data */
	if (packer->cpf.flush(packer->cpf.state) != BSDIFF_SUCCESS) return BSDIFF_ERROR;

	if (packer->cpf.get_buffer(packer->cpf.state, (const void **)&uncompressed_data, &uncompressed_len) !=
	    BSDIFF_SUCCESS)
		return BSDIFF_ERROR;

	/* Find best compression for ctrl data */
	if (find_best_compression(uncompressed_data, uncompressed_len, &compressed_ctrl, &compressed_ctrl_len,
	                          &ctrl_type) != BSDIFF_SUCCESS)
		return BSDIFF_ERROR;

	/* write compress ctrl length to header */
	offtout((int64_t)compressed_ctrl_len, header + 8);

	/* Find best compression for diff data */
	if (find_best_compression(packer->db, (size_t)packer->dblen, &compressed_diff, &compressed_diff_len, &diff_type) !=
	    BSDIFF_SUCCESS) {
		free(compressed_ctrl);
		return BSDIFF_ERROR;
	}

	/* write compress diff length to header */
	offtout((int64_t)compressed_diff_len, header + 16);

	/* Find best compression for extra data */
	if (find_best_compression(packer->eb, (size_t)packer->eblen, &compressed_extra, &compressed_extra_len,
	                          &extra_type) != BSDIFF_SUCCESS) {
		free(compressed_ctrl);
		free(compressed_diff);
		return BSDIFF_ERROR;
	}
	/* write compression method to header */
	if (ctrl_type != 'B' || diff_type != 'B' || extra_type != 'B') {
		memcpy(header, "BSDFM", 5);
		header[5] = ctrl_type;
		header[6] = diff_type;
		header[7] = extra_type;
	}

	/* write header */
	if (packer->stream->write(packer->stream->state, header, 32) != BSDIFF_SUCCESS) {
		result = BSDIFF_FILE_ERROR;
		goto cleanup;
	}
	/* write compressed ctrl data */
	if (packer->stream->write(packer->stream->state, compressed_ctrl, compressed_ctrl_len) != BSDIFF_SUCCESS) {
		result = BSDIFF_FILE_ERROR;
		goto cleanup;
	}

	/* write compressed diff data */
	if (packer->stream->write(packer->stream->state, compressed_diff, compressed_diff_len) != BSDIFF_SUCCESS) {
		result = BSDIFF_FILE_ERROR;
		goto cleanup;
	}

	/* write compressed extra data */
	if (packer->stream->write(packer->stream->state, compressed_extra, compressed_extra_len) != BSDIFF_SUCCESS) {
		result = BSDIFF_FILE_ERROR;
		goto cleanup;
	}

	/* flush the stream */
	if ((packer->stream->flush(packer->stream->state) != BSDIFF_SUCCESS)) {
		result = BSDIFF_FILE_ERROR;
		goto cleanup;
	}

cleanup:
	free(compressed_ctrl);
	free(compressed_diff);
	free(compressed_extra);
	return result;
}

static void maa_patch_packer_close(void *state) {
	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;

	if (packer->mode == BSDIFF_MODE_READ) {
		bsdiff_close_decompressor(&(packer->cpf_dec));
		bsdiff_close_decompressor(&(packer->dpf_dec));
		bsdiff_close_decompressor(&(packer->epf_dec));
		bsdiff_close_stream(&(packer->cpf));
		bsdiff_close_stream(&(packer->dpf));
		bsdiff_close_stream(&(packer->epf));
	} else {
		bsdiff_close_stream(&(packer->cpf));
		free(packer->db);
		free(packer->eb);
	}

	bsdiff_close_stream(packer->stream);

	free(packer);
}

static int maa_patch_packer_getmode(void *state) {
	struct maa_patch_packer *packer = (struct maa_patch_packer *)state;
	return packer->mode;
}

int bsdiff_open_maa_patch_packer(int mode, struct bsdiff_stream *stream, struct bsdiff_patch_packer *packer) {
	struct maa_patch_packer *state;
	assert(mode >= BSDIFF_MODE_READ && mode <= BSDIFF_MODE_WRITE);
	assert(stream);
	assert(packer);

	state = malloc(sizeof(struct maa_patch_packer));
	if (!state) return BSDIFF_OUT_OF_MEMORY;
	memset(state, 0, sizeof(*state));
	state->stream = stream;
	state->mode = mode;
	state->new_size = -1;

	memset(packer, 0, sizeof(*packer));
	packer->state = state;
	if (mode == BSDIFF_MODE_READ) {
		packer->read_new_size = maa_patch_packer_read_new_size;
		packer->read_entry_header = maa_patch_packer_read_entry_header;
		packer->read_entry_diff = maa_patch_packer_read_entry_diff;
		packer->read_entry_extra = maa_patch_packer_read_entry_extra;
	} else {
		packer->write_new_size = maa_patch_packer_write_new_size;
		packer->write_entry_header = maa_patch_packer_write_entry_header;
		packer->write_entry_diff = maa_patch_packer_write_entry_diff;
		packer->write_entry_extra = maa_patch_packer_write_entry_extra;
		packer->flush = maa_patch_packer_flush;
	}
	packer->close = maa_patch_packer_close;
	packer->get_mode = maa_patch_packer_getmode;

	return BSDIFF_SUCCESS;
}
