// This file is generated. Do not edit.
#ifndef VP8_RTCD_H_
#define VP8_RTCD_H_

#ifdef RTCD_C
#define RTCD_EXTERN
#else
#define RTCD_EXTERN extern
#endif

/*
 * VP8
 */

struct blockd;
struct macroblockd;
struct loop_filter_info;

/* Encoder forward decls */
struct block;
struct macroblock;
struct variance_vtable;
union int_mv;
struct yv12_buffer_config;

#ifdef __cplusplus
extern "C" {
#endif

void vp8_bilinear_predict16x16_c(unsigned char *src, int src_pitch, int xofst,
                                 int yofst, unsigned char *dst, int dst_pitch);
void vp8_bilinear_predict16x16_sse2(unsigned char *src, int src_pitch,
                                    int xofst, int yofst, unsigned char *dst,
                                    int dst_pitch);
void vp8_bilinear_predict16x16_ssse3(unsigned char *src, int src_pitch,
                                     int xofst, int yofst, unsigned char *dst,
                                     int dst_pitch);
RTCD_EXTERN void (*vp8_bilinear_predict16x16)(unsigned char *src, int src_pitch,
                                              int xofst, int yofst,
                                              unsigned char *dst,
                                              int dst_pitch);

void vp8_bilinear_predict4x4_c(unsigned char *src, int src_pitch, int xofst,
                               int yofst, unsigned char *dst, int dst_pitch);
void vp8_bilinear_predict4x4_mmx(unsigned char *src, int src_pitch, int xofst,
                                 int yofst, unsigned char *dst, int dst_pitch);
RTCD_EXTERN void (*vp8_bilinear_predict4x4)(unsigned char *src, int src_pitch,
                                            int xofst, int yofst,
                                            unsigned char *dst, int dst_pitch);

void vp8_bilinear_predict8x4_c(unsigned char *src, int src_pitch, int xofst,
                               int yofst, unsigned char *dst, int dst_pitch);
void vp8_bilinear_predict8x4_mmx(unsigned char *src, int src_pitch, int xofst,
                                 int yofst, unsigned char *dst, int dst_pitch);
RTCD_EXTERN void (*vp8_bilinear_predict8x4)(unsigned char *src, int src_pitch,
                                            int xofst, int yofst,
                                            unsigned char *dst, int dst_pitch);

void vp8_bilinear_predict8x8_c(unsigned char *src, int src_pitch, int xofst,
                               int yofst, unsigned char *dst, int dst_pitch);
void vp8_bilinear_predict8x8_sse2(unsigned char *src, int src_pitch, int xofst,
                                  int yofst, unsigned char *dst, int dst_pitch);
void vp8_bilinear_predict8x8_ssse3(unsigned char *src, int src_pitch, int xofst,
                                   int yofst, unsigned char *dst,
                                   int dst_pitch);
RTCD_EXTERN void (*vp8_bilinear_predict8x8)(unsigned char *src, int src_pitch,
                                            int xofst, int yofst,
                                            unsigned char *dst, int dst_pitch);

void vp8_blend_b_c(unsigned char *y, unsigned char *u, unsigned char *v, int y1,
                   int u1, int v1, int alpha, int stride);
#define vp8_blend_b vp8_blend_b_c

void vp8_blend_mb_inner_c(unsigned char *y, unsigned char *u, unsigned char *v,
                          int y1, int u1, int v1, int alpha, int stride);
#define vp8_blend_mb_inner vp8_blend_mb_inner_c

void vp8_blend_mb_outer_c(unsigned char *y, unsigned char *u, unsigned char *v,
                          int y1, int u1, int v1, int alpha, int stride);
#define vp8_blend_mb_outer vp8_blend_mb_outer_c

int vp8_block_error_c(short *coeff, short *dqcoeff);
int vp8_block_error_sse2(short *coeff, short *dqcoeff);
RTCD_EXTERN int (*vp8_block_error)(short *coeff, short *dqcoeff);

void vp8_copy32xn_c(const unsigned char *src_ptr, int source_stride,
                    unsigned char *dst_ptr, int dst_stride, int n);
void vp8_copy32xn_sse2(const unsigned char *src_ptr, int source_stride,
                       unsigned char *dst_ptr, int dst_stride, int n);
void vp8_copy32xn_sse3(const unsigned char *src_ptr, int source_stride,
                       unsigned char *dst_ptr, int dst_stride, int n);
RTCD_EXTERN void (*vp8_copy32xn)(const unsigned char *src_ptr,
                                 int source_stride, unsigned char *dst_ptr,
                                 int dst_stride, int n);

void vp8_copy_mem16x16_c(unsigned char *src, int src_pitch, unsigned char *dst,
                         int dst_pitch);
void vp8_copy_mem16x16_sse2(unsigned char *src, int src_pitch,
                            unsigned char *dst, int dst_pitch);
RTCD_EXTERN void (*vp8_copy_mem16x16)(unsigned char *src, int src_pitch,
                                      unsigned char *dst, int dst_pitch);

void vp8_copy_mem8x4_c(unsigned char *src, int src_pitch, unsigned char *dst,
                       int dst_pitch);
void vp8_copy_mem8x4_mmx(unsigned char *src, int src_pitch, unsigned char *dst,
                         int dst_pitch);
RTCD_EXTERN void (*vp8_copy_mem8x4)(unsigned char *src, int src_pitch,
                                    unsigned char *dst, int dst_pitch);

void vp8_copy_mem8x8_c(unsigned char *src, int src_pitch, unsigned char *dst,
                       int dst_pitch);
void vp8_copy_mem8x8_mmx(unsigned char *src, int src_pitch, unsigned char *dst,
                         int dst_pitch);
RTCD_EXTERN void (*vp8_copy_mem8x8)(unsigned char *src, int src_pitch,
                                    unsigned char *dst, int dst_pitch);

void vp8_dc_only_idct_add_c(short input, unsigned char *pred, int pred_stride,
                            unsigned char *dst, int dst_stride);
void vp8_dc_only_idct_add_mmx(short input, unsigned char *pred, int pred_stride,
                              unsigned char *dst, int dst_stride);
RTCD_EXTERN void (*vp8_dc_only_idct_add)(short input, unsigned char *pred,
                                         int pred_stride, unsigned char *dst,
                                         int dst_stride);

int vp8_denoiser_filter_c(unsigned char *mc_running_avg_y, int mc_avg_y_stride,
                          unsigned char *running_avg_y, int avg_y_stride,
                          unsigned char *sig, int sig_stride,
                          unsigned int motion_magnitude,
                          int increase_denoising);
int vp8_denoiser_filter_sse2(unsigned char *mc_running_avg_y,
                             int mc_avg_y_stride, unsigned char *running_avg_y,
                             int avg_y_stride, unsigned char *sig,
                             int sig_stride, unsigned int motion_magnitude,
                             int increase_denoising);
RTCD_EXTERN int (*vp8_denoiser_filter)(
    unsigned char *mc_running_avg_y, int mc_avg_y_stride,
    unsigned char *running_avg_y, int avg_y_stride, unsigned char *sig,
    int sig_stride, unsigned int motion_magnitude, int increase_denoising);

int vp8_denoiser_filter_uv_c(unsigned char *mc_running_avg, int mc_avg_stride,
                             unsigned char *running_avg, int avg_stride,
                             unsigned char *sig, int sig_stride,
                             unsigned int motion_magnitude,
                             int increase_denoising);
int vp8_denoiser_filter_uv_sse2(unsigned char *mc_running_avg,
                                int mc_avg_stride, unsigned char *running_avg,
                                int avg_stride, unsigned char *sig,
                                int sig_stride, unsigned int motion_magnitude,
                                int increase_denoising);
RTCD_EXTERN int (*vp8_denoiser_filter_uv)(
    unsigned char *mc_running_avg, int mc_avg_stride,
    unsigned char *running_avg, int avg_stride, unsigned char *sig,
    int sig_stride, unsigned int motion_magnitude, int increase_denoising);

void vp8_dequant_idct_add_c(short *input, short *dq, unsigned char *output,
                            int stride);
void vp8_dequant_idct_add_mmx(short *input, short *dq, unsigned char *output,
                              int stride);
RTCD_EXTERN void (*vp8_dequant_idct_add)(short *input, short *dq,
                                         unsigned char *output, int stride);

void vp8_dequant_idct_add_uv_block_c(short *q, short *dq, unsigned char *dst_u,
                                     unsigned char *dst_v, int stride,
                                     char *eobs);
void vp8_dequant_idct_add_uv_block_sse2(short *q, short *dq,
                                        unsigned char *dst_u,
                                        unsigned char *dst_v, int stride,
                                        char *eobs);
RTCD_EXTERN void (*vp8_dequant_idct_add_uv_block)(short *q, short *dq,
                                                  unsigned char *dst_u,
                                                  unsigned char *dst_v,
                                                  int stride, char *eobs);

void vp8_dequant_idct_add_y_block_c(short *q, short *dq, unsigned char *dst,
                                    int stride, char *eobs);
void vp8_dequant_idct_add_y_block_sse2(short *q, short *dq, unsigned char *dst,
                                       int stride, char *eobs);
RTCD_EXTERN void (*vp8_dequant_idct_add_y_block)(short *q, short *dq,
                                                 unsigned char *dst, int stride,
                                                 char *eobs);

void vp8_dequantize_b_c(struct blockd *, short *dqc);
void vp8_dequantize_b_mmx(struct blockd *, short *dqc);
RTCD_EXTERN void (*vp8_dequantize_b)(struct blockd *, short *dqc);

int vp8_diamond_search_sad_c(struct macroblock *x, struct block *b,
                             struct blockd *d, union int_mv *ref_mv,
                             union int_mv *best_mv, int search_param,
                             int sad_per_bit, int *num00,
                             struct variance_vtable *fn_ptr, int *mvcost[2],
                             union int_mv *center_mv);
int vp8_diamond_search_sadx4(struct macroblock *x, struct block *b,
                             struct blockd *d, union int_mv *ref_mv,
                             union int_mv *best_mv, int search_param,
                             int sad_per_bit, int *num00,
                             struct variance_vtable *fn_ptr, int *mvcost[2],
                             union int_mv *center_mv);
RTCD_EXTERN int (*vp8_diamond_search_sad)(
    struct macroblock *x, struct block *b, struct blockd *d,
    union int_mv *ref_mv, union int_mv *best_mv, int search_param,
    int sad_per_bit, int *num00, struct variance_vtable *fn_ptr, int *mvcost[2],
    union int_mv *center_mv);

void vp8_fast_quantize_b_c(struct block *, struct blockd *);
void vp8_fast_quantize_b_sse2(struct block *, struct blockd *);
void vp8_fast_quantize_b_ssse3(struct block *, struct blockd *);
RTCD_EXTERN void (*vp8_fast_quantize_b)(struct block *, struct blockd *);

void vp8_filter_by_weight16x16_c(unsigned char *src, int src_stride,
                                 unsigned char *dst, int dst_stride,
                                 int src_weight);
void vp8_filter_by_weight16x16_sse2(unsigned char *src, int src_stride,
                                    unsigned char *dst, int dst_stride,
                                    int src_weight);
RTCD_EXTERN void (*vp8_filter_by_weight16x16)(unsigned char *src,
                                              int src_stride,
                                              unsigned char *dst,
                                              int dst_stride, int src_weight);

void vp8_filter_by_weight4x4_c(unsigned char *src, int src_stride,
                               unsigned char *dst, int dst_stride,
                               int src_weight);
#define vp8_filter_by_weight4x4 vp8_filter_by_weight4x4_c

void vp8_filter_by_weight8x8_c(unsigned char *src, int src_stride,
                               unsigned char *dst, int dst_stride,
                               int src_weight);
void vp8_filter_by_weight8x8_sse2(unsigned char *src, int src_stride,
                                  unsigned char *dst, int dst_stride,
                                  int src_weight);
RTCD_EXTERN void (*vp8_filter_by_weight8x8)(unsigned char *src, int src_stride,
                                            unsigned char *dst, int dst_stride,
                                            int src_weight);

int vp8_full_search_sad_c(struct macroblock *x, struct block *b,
                          struct blockd *d, union int_mv *ref_mv,
                          int sad_per_bit, int distance,
                          struct variance_vtable *fn_ptr, int *mvcost[2],
                          union int_mv *center_mv);
int vp8_full_search_sadx3(struct macroblock *x, struct block *b,
                          struct blockd *d, union int_mv *ref_mv,
                          int sad_per_bit, int distance,
                          struct variance_vtable *fn_ptr, int *mvcost[2],
                          union int_mv *center_mv);
int vp8_full_search_sadx8(struct macroblock *x, struct block *b,
                          struct blockd *d, union int_mv *ref_mv,
                          int sad_per_bit, int distance,
                          struct variance_vtable *fn_ptr, int *mvcost[2],
                          union int_mv *center_mv);
RTCD_EXTERN int (*vp8_full_search_sad)(struct macroblock *x, struct block *b,
                                       struct blockd *d, union int_mv *ref_mv,
                                       int sad_per_bit, int distance,
                                       struct variance_vtable *fn_ptr,
                                       int *mvcost[2], union int_mv *center_mv);

void vp8_loop_filter_bh_c(unsigned char *y, unsigned char *u, unsigned char *v,
                          int ystride, int uv_stride,
                          struct loop_filter_info *lfi);
void vp8_loop_filter_bh_sse2(unsigned char *y, unsigned char *u,
                             unsigned char *v, int ystride, int uv_stride,
                             struct loop_filter_info *lfi);
RTCD_EXTERN void (*vp8_loop_filter_bh)(unsigned char *y, unsigned char *u,
                                       unsigned char *v, int ystride,
                                       int uv_stride,
                                       struct loop_filter_info *lfi);

void vp8_loop_filter_bv_c(unsigned char *y, unsigned char *u, unsigned char *v,
                          int ystride, int uv_stride,
                          struct loop_filter_info *lfi);
void vp8_loop_filter_bv_sse2(unsigned char *y, unsigned char *u,
                             unsigned char *v, int ystride, int uv_stride,
                             struct loop_filter_info *lfi);
RTCD_EXTERN void (*vp8_loop_filter_bv)(unsigned char *y, unsigned char *u,
                                       unsigned char *v, int ystride,
                                       int uv_stride,
                                       struct loop_filter_info *lfi);

void vp8_loop_filter_mbh_c(unsigned char *y, unsigned char *u, unsigned char *v,
                           int ystride, int uv_stride,
                           struct loop_filter_info *lfi);
void vp8_loop_filter_mbh_sse2(unsigned char *y, unsigned char *u,
                              unsigned char *v, int ystride, int uv_stride,
                              struct loop_filter_info *lfi);
RTCD_EXTERN void (*vp8_loop_filter_mbh)(unsigned char *y, unsigned char *u,
                                        unsigned char *v, int ystride,
                                        int uv_stride,
                                        struct loop_filter_info *lfi);

void vp8_loop_filter_mbv_c(unsigned char *y, unsigned char *u, unsigned char *v,
                           int ystride, int uv_stride,
                           struct loop_filter_info *lfi);
void vp8_loop_filter_mbv_sse2(unsigned char *y, unsigned char *u,
                              unsigned char *v, int ystride, int uv_stride,
                              struct loop_filter_info *lfi);
RTCD_EXTERN void (*vp8_loop_filter_mbv)(unsigned char *y, unsigned char *u,
                                        unsigned char *v, int ystride,
                                        int uv_stride,
                                        struct loop_filter_info *lfi);

void vp8_loop_filter_bhs_c(unsigned char *y, int ystride,
                           const unsigned char *blimit);
void vp8_loop_filter_bhs_sse2(unsigned char *y, int ystride,
                              const unsigned char *blimit);
RTCD_EXTERN void (*vp8_loop_filter_simple_bh)(unsigned char *y, int ystride,
                                              const unsigned char *blimit);

void vp8_loop_filter_bvs_c(unsigned char *y, int ystride,
                           const unsigned char *blimit);
void vp8_loop_filter_bvs_sse2(unsigned char *y, int ystride,
                              const unsigned char *blimit);
RTCD_EXTERN void (*vp8_loop_filter_simple_bv)(unsigned char *y, int ystride,
                                              const unsigned char *blimit);

void vp8_loop_filter_simple_horizontal_edge_c(unsigned char *y, int ystride,
                                              const unsigned char *blimit);
void vp8_loop_filter_simple_horizontal_edge_sse2(unsigned char *y, int ystride,
                                                 const unsigned char *blimit);
RTCD_EXTERN void (*vp8_loop_filter_simple_mbh)(unsigned char *y, int ystride,
                                               const unsigned char *blimit);

void vp8_loop_filter_simple_vertical_edge_c(unsigned char *y, int ystride,
                                            const unsigned char *blimit);
void vp8_loop_filter_simple_vertical_edge_sse2(unsigned char *y, int ystride,
                                               const unsigned char *blimit);
RTCD_EXTERN void (*vp8_loop_filter_simple_mbv)(unsigned char *y, int ystride,
                                               const unsigned char *blimit);

int vp8_mbblock_error_c(struct macroblock *mb, int dc);
int vp8_mbblock_error_sse2(struct macroblock *mb, int dc);
RTCD_EXTERN int (*vp8_mbblock_error)(struct macroblock *mb, int dc);

int vp8_mbuverror_c(struct macroblock *mb);
int vp8_mbuverror_sse2(struct macroblock *mb);
RTCD_EXTERN int (*vp8_mbuverror)(struct macroblock *mb);

int vp8_refining_search_sad_c(struct macroblock *x, struct block *b,
                              struct blockd *d, union int_mv *ref_mv,
                              int sad_per_bit, int distance,
                              struct variance_vtable *fn_ptr, int *mvcost[2],
                              union int_mv *center_mv);
int vp8_refining_search_sadx4(struct macroblock *x, struct block *b,
                              struct blockd *d, union int_mv *ref_mv,
                              int sad_per_bit, int distance,
                              struct variance_vtable *fn_ptr, int *mvcost[2],
                              union int_mv *center_mv);
RTCD_EXTERN int (*vp8_refining_search_sad)(
    struct macroblock *x, struct block *b, struct blockd *d,
    union int_mv *ref_mv, int sad_per_bit, int distance,
    struct variance_vtable *fn_ptr, int *mvcost[2], union int_mv *center_mv);

void vp8_regular_quantize_b_c(struct block *, struct blockd *);
void vp8_regular_quantize_b_sse2(struct block *, struct blockd *);
void vp8_regular_quantize_b_sse4_1(struct block *, struct blockd *);
RTCD_EXTERN void (*vp8_regular_quantize_b)(struct block *, struct blockd *);

void vp8_short_fdct4x4_c(short *input, short *output, int pitch);
void vp8_short_fdct4x4_sse2(short *input, short *output, int pitch);
RTCD_EXTERN void (*vp8_short_fdct4x4)(short *input, short *output, int pitch);

void vp8_short_fdct8x4_c(short *input, short *output, int pitch);
void vp8_short_fdct8x4_sse2(short *input, short *output, int pitch);
RTCD_EXTERN void (*vp8_short_fdct8x4)(short *input, short *output, int pitch);

void vp8_short_idct4x4llm_c(short *input, unsigned char *pred, int pitch,
                            unsigned char *dst, int dst_stride);
void vp8_short_idct4x4llm_mmx(short *input, unsigned char *pred, int pitch,
                              unsigned char *dst, int dst_stride);
RTCD_EXTERN void (*vp8_short_idct4x4llm)(short *input, unsigned char *pred,
                                         int pitch, unsigned char *dst,
                                         int dst_stride);

void vp8_short_inv_walsh4x4_c(short *input, short *output);
void vp8_short_inv_walsh4x4_sse2(short *input, short *output);
RTCD_EXTERN void (*vp8_short_inv_walsh4x4)(short *input, short *output);

void vp8_short_inv_walsh4x4_1_c(short *input, short *output);
#define vp8_short_inv_walsh4x4_1 vp8_short_inv_walsh4x4_1_c

void vp8_short_walsh4x4_c(short *input, short *output, int pitch);
void vp8_short_walsh4x4_sse2(short *input, short *output, int pitch);
RTCD_EXTERN void (*vp8_short_walsh4x4)(short *input, short *output, int pitch);

void vp8_sixtap_predict16x16_c(unsigned char *src, int src_pitch, int xofst,
                               int yofst, unsigned char *dst, int dst_pitch);
void vp8_sixtap_predict16x16_sse2(unsigned char *src, int src_pitch, int xofst,
                                  int yofst, unsigned char *dst, int dst_pitch);
void vp8_sixtap_predict16x16_ssse3(unsigned char *src, int src_pitch, int xofst,
                                   int yofst, unsigned char *dst,
                                   int dst_pitch);
RTCD_EXTERN void (*vp8_sixtap_predict16x16)(unsigned char *src, int src_pitch,
                                            int xofst, int yofst,
                                            unsigned char *dst, int dst_pitch);

void vp8_sixtap_predict4x4_c(unsigned char *src, int src_pitch, int xofst,
                             int yofst, unsigned char *dst, int dst_pitch);
void vp8_sixtap_predict4x4_mmx(unsigned char *src, int src_pitch, int xofst,
                               int yofst, unsigned char *dst, int dst_pitch);
void vp8_sixtap_predict4x4_ssse3(unsigned char *src, int src_pitch, int xofst,
                                 int yofst, unsigned char *dst, int dst_pitch);
RTCD_EXTERN void (*vp8_sixtap_predict4x4)(unsigned char *src, int src_pitch,
                                          int xofst, int yofst,
                                          unsigned char *dst, int dst_pitch);

void vp8_sixtap_predict8x4_c(unsigned char *src, int src_pitch, int xofst,
                             int yofst, unsigned char *dst, int dst_pitch);
void vp8_sixtap_predict8x4_sse2(unsigned char *src, int src_pitch, int xofst,
                                int yofst, unsigned char *dst, int dst_pitch);
void vp8_sixtap_predict8x4_ssse3(unsigned char *src, int src_pitch, int xofst,
                                 int yofst, unsigned char *dst, int dst_pitch);
RTCD_EXTERN void (*vp8_sixtap_predict8x4)(unsigned char *src, int src_pitch,
                                          int xofst, int yofst,
                                          unsigned char *dst, int dst_pitch);

void vp8_sixtap_predict8x8_c(unsigned char *src, int src_pitch, int xofst,
                             int yofst, unsigned char *dst, int dst_pitch);
void vp8_sixtap_predict8x8_sse2(unsigned char *src, int src_pitch, int xofst,
                                int yofst, unsigned char *dst, int dst_pitch);
void vp8_sixtap_predict8x8_ssse3(unsigned char *src, int src_pitch, int xofst,
                                 int yofst, unsigned char *dst, int dst_pitch);
RTCD_EXTERN void (*vp8_sixtap_predict8x8)(unsigned char *src, int src_pitch,
                                          int xofst, int yofst,
                                          unsigned char *dst, int dst_pitch);

void vp8_rtcd(void);

#ifdef RTCD_C
#include "vpx_ports/x86.h"
static void setup_rtcd_internal(void) {
  int flags = x86_simd_caps();

  (void)flags;

  vp8_bilinear_predict16x16 = vp8_bilinear_predict16x16_c;
  if (flags & HAS_SSE2)
    vp8_bilinear_predict16x16 = vp8_bilinear_predict16x16_sse2;
  if (flags & HAS_SSSE3)
    vp8_bilinear_predict16x16 = vp8_bilinear_predict16x16_ssse3;
  vp8_bilinear_predict4x4 = vp8_bilinear_predict4x4_c;
  if (flags & HAS_MMX) vp8_bilinear_predict4x4 = vp8_bilinear_predict4x4_mmx;
  vp8_bilinear_predict8x4 = vp8_bilinear_predict8x4_c;
  if (flags & HAS_MMX) vp8_bilinear_predict8x4 = vp8_bilinear_predict8x4_mmx;
  vp8_bilinear_predict8x8 = vp8_bilinear_predict8x8_c;
  if (flags & HAS_SSE2) vp8_bilinear_predict8x8 = vp8_bilinear_predict8x8_sse2;
  if (flags & HAS_SSSE3)
    vp8_bilinear_predict8x8 = vp8_bilinear_predict8x8_ssse3;
  vp8_block_error = vp8_block_error_c;
  if (flags & HAS_SSE2) vp8_block_error = vp8_block_error_sse2;
  vp8_copy32xn = vp8_copy32xn_c;
  if (flags & HAS_SSE2) vp8_copy32xn = vp8_copy32xn_sse2;
  if (flags & HAS_SSE3) vp8_copy32xn = vp8_copy32xn_sse3;
  vp8_copy_mem16x16 = vp8_copy_mem16x16_c;
  if (flags & HAS_SSE2) vp8_copy_mem16x16 = vp8_copy_mem16x16_sse2;
  vp8_copy_mem8x4 = vp8_copy_mem8x4_c;
  if (flags & HAS_MMX) vp8_copy_mem8x4 = vp8_copy_mem8x4_mmx;
  vp8_copy_mem8x8 = vp8_copy_mem8x8_c;
  if (flags & HAS_MMX) vp8_copy_mem8x8 = vp8_copy_mem8x8_mmx;
  vp8_dc_only_idct_add = vp8_dc_only_idct_add_c;
  if (flags & HAS_MMX) vp8_dc_only_idct_add = vp8_dc_only_idct_add_mmx;
  vp8_denoiser_filter = vp8_denoiser_filter_c;
  if (flags & HAS_SSE2) vp8_denoiser_filter = vp8_denoiser_filter_sse2;
  vp8_denoiser_filter_uv = vp8_denoiser_filter_uv_c;
  if (flags & HAS_SSE2) vp8_denoiser_filter_uv = vp8_denoiser_filter_uv_sse2;
  vp8_dequant_idct_add = vp8_dequant_idct_add_c;
  if (flags & HAS_MMX) vp8_dequant_idct_add = vp8_dequant_idct_add_mmx;
  vp8_dequant_idct_add_uv_block = vp8_dequant_idct_add_uv_block_c;
  if (flags & HAS_SSE2)
    vp8_dequant_idct_add_uv_block = vp8_dequant_idct_add_uv_block_sse2;
  vp8_dequant_idct_add_y_block = vp8_dequant_idct_add_y_block_c;
  if (flags & HAS_SSE2)
    vp8_dequant_idct_add_y_block = vp8_dequant_idct_add_y_block_sse2;
  vp8_dequantize_b = vp8_dequantize_b_c;
  if (flags & HAS_MMX) vp8_dequantize_b = vp8_dequantize_b_mmx;
  vp8_diamond_search_sad = vp8_diamond_search_sad_c;
  if (flags & HAS_SSE2) vp8_diamond_search_sad = vp8_diamond_search_sadx4;
  vp8_fast_quantize_b = vp8_fast_quantize_b_c;
  if (flags & HAS_SSE2) vp8_fast_quantize_b = vp8_fast_quantize_b_sse2;
  if (flags & HAS_SSSE3) vp8_fast_quantize_b = vp8_fast_quantize_b_ssse3;
  vp8_filter_by_weight16x16 = vp8_filter_by_weight16x16_c;
  if (flags & HAS_SSE2)
    vp8_filter_by_weight16x16 = vp8_filter_by_weight16x16_sse2;
  vp8_filter_by_weight8x8 = vp8_filter_by_weight8x8_c;
  if (flags & HAS_SSE2) vp8_filter_by_weight8x8 = vp8_filter_by_weight8x8_sse2;
  vp8_full_search_sad = vp8_full_search_sad_c;
  if (flags & HAS_SSE3) vp8_full_search_sad = vp8_full_search_sadx3;
  if (flags & HAS_SSE4_1) vp8_full_search_sad = vp8_full_search_sadx8;
  vp8_loop_filter_bh = vp8_loop_filter_bh_c;
  if (flags & HAS_SSE2) vp8_loop_filter_bh = vp8_loop_filter_bh_sse2;
  vp8_loop_filter_bv = vp8_loop_filter_bv_c;
  if (flags & HAS_SSE2) vp8_loop_filter_bv = vp8_loop_filter_bv_sse2;
  vp8_loop_filter_mbh = vp8_loop_filter_mbh_c;
  if (flags & HAS_SSE2) vp8_loop_filter_mbh = vp8_loop_filter_mbh_sse2;
  vp8_loop_filter_mbv = vp8_loop_filter_mbv_c;
  if (flags & HAS_SSE2) vp8_loop_filter_mbv = vp8_loop_filter_mbv_sse2;
  vp8_loop_filter_simple_bh = vp8_loop_filter_bhs_c;
  if (flags & HAS_SSE2) vp8_loop_filter_simple_bh = vp8_loop_filter_bhs_sse2;
  vp8_loop_filter_simple_bv = vp8_loop_filter_bvs_c;
  if (flags & HAS_SSE2) vp8_loop_filter_simple_bv = vp8_loop_filter_bvs_sse2;
  vp8_loop_filter_simple_mbh = vp8_loop_filter_simple_horizontal_edge_c;
  if (flags & HAS_SSE2)
    vp8_loop_filter_simple_mbh = vp8_loop_filter_simple_horizontal_edge_sse2;
  vp8_loop_filter_simple_mbv = vp8_loop_filter_simple_vertical_edge_c;
  if (flags & HAS_SSE2)
    vp8_loop_filter_simple_mbv = vp8_loop_filter_simple_vertical_edge_sse2;
  vp8_mbblock_error = vp8_mbblock_error_c;
  if (flags & HAS_SSE2) vp8_mbblock_error = vp8_mbblock_error_sse2;
  vp8_mbuverror = vp8_mbuverror_c;
  if (flags & HAS_SSE2) vp8_mbuverror = vp8_mbuverror_sse2;
  vp8_refining_search_sad = vp8_refining_search_sad_c;
  if (flags & HAS_SSE2) vp8_refining_search_sad = vp8_refining_search_sadx4;
  vp8_regular_quantize_b = vp8_regular_quantize_b_c;
  if (flags & HAS_SSE2) vp8_regular_quantize_b = vp8_regular_quantize_b_sse2;
  if (flags & HAS_SSE4_1)
    vp8_regular_quantize_b = vp8_regular_quantize_b_sse4_1;
  vp8_short_fdct4x4 = vp8_short_fdct4x4_c;
  if (flags & HAS_SSE2) vp8_short_fdct4x4 = vp8_short_fdct4x4_sse2;
  vp8_short_fdct8x4 = vp8_short_fdct8x4_c;
  if (flags & HAS_SSE2) vp8_short_fdct8x4 = vp8_short_fdct8x4_sse2;
  vp8_short_idct4x4llm = vp8_short_idct4x4llm_c;
  if (flags & HAS_MMX) vp8_short_idct4x4llm = vp8_short_idct4x4llm_mmx;
  vp8_short_inv_walsh4x4 = vp8_short_inv_walsh4x4_c;
  if (flags & HAS_SSE2) vp8_short_inv_walsh4x4 = vp8_short_inv_walsh4x4_sse2;
  vp8_short_walsh4x4 = vp8_short_walsh4x4_c;
  if (flags & HAS_SSE2) vp8_short_walsh4x4 = vp8_short_walsh4x4_sse2;
  vp8_sixtap_predict16x16 = vp8_sixtap_predict16x16_c;
  if (flags & HAS_SSE2) vp8_sixtap_predict16x16 = vp8_sixtap_predict16x16_sse2;
  if (flags & HAS_SSSE3)
    vp8_sixtap_predict16x16 = vp8_sixtap_predict16x16_ssse3;
  vp8_sixtap_predict4x4 = vp8_sixtap_predict4x4_c;
  if (flags & HAS_MMX) vp8_sixtap_predict4x4 = vp8_sixtap_predict4x4_mmx;
  if (flags & HAS_SSSE3) vp8_sixtap_predict4x4 = vp8_sixtap_predict4x4_ssse3;
  vp8_sixtap_predict8x4 = vp8_sixtap_predict8x4_c;
  if (flags & HAS_SSE2) vp8_sixtap_predict8x4 = vp8_sixtap_predict8x4_sse2;
  if (flags & HAS_SSSE3) vp8_sixtap_predict8x4 = vp8_sixtap_predict8x4_ssse3;
  vp8_sixtap_predict8x8 = vp8_sixtap_predict8x8_c;
  if (flags & HAS_SSE2) vp8_sixtap_predict8x8 = vp8_sixtap_predict8x8_sse2;
  if (flags & HAS_SSSE3) vp8_sixtap_predict8x8 = vp8_sixtap_predict8x8_ssse3;
}
#endif

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
