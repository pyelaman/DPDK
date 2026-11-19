/**
 * ==================================================================================
 * ALKIRA DATA PLANE ARCHITECTURE SUB-SYSTEM: BIT MANIPULATION & VECTORIZATION ENGINE
 * ==================================================================================
 *
 * This implementation consolidates four critical high-throughput, branch-free 
 * packet operations designed for multi-gigabit line rates:
 *
 * 1. Vector Masking and Header Extraction (AVX-512 & BMI2)
 *    Extracts non-contiguous, byte-unaligned VNI fields and control bits out of 
 *    nested headers simultaneously without scalar iteration penalty loops.
 *
 * 2. Variable-Length Header Profiling via SIMD Mask Conversion
 *    Extracts the 4-bit IHL (Internet Header Length) dynamically from a parallel burst 
 *    of packets to compute downstream transport offsets in a unified vector lane.
 *
 * 3. High-Performance Policy Lookup Matching via Compressed Bitmaps
 *    Transforms vectorized lookup match registers (k-registers) into scalar tracking paths
 *    using hardware-accelerated trailing-zero counting (`_tzcnt_u64`).
 *
 * 4. Symmetrical Hash Generation & Endianness Bit-Reversals
 *    Sorts IP pairs element-wise using parallel min/max algorithms to guarantee 
 *    symmetrical flow calculations while correcting network-to-host byte orders in one cycle.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

/* --- COMPILE TIME DEFINITIONS & STRUCTS --- */
#define BURST_SIZE 16

typedef struct {
    uint32_t extracted_vni;
    uint8_t  extracted_flags;
} __attribute__((packed)) parsing_result_t;

/* ==================================================================================
 * OPERATION 1: VECTOR MASKING AND HEADER EXTRACTION (BMI2 & AVX-512)
 * ================================================================================== */

/**
 * Uses the BMI2 instruction '_pext_u64' (Parallel Bit Extract) to gather scattered, 
 * unaligned bit paths into a compressed contiguous integer.
 */
inline parsing_result_t extract_fields_unaligned_bmi2(uint64_t raw_header_qword) {
    parsing_result_t result;

    // Isolate a 24-bit VNI pattern scattered across the middle byte boundaries (bytes 2, 3, and 4)
    uint64_t vni_mask = 0x000000FFFFFF0000ULL;
    result.extracted_vni = (uint32_t)_pext_u64(raw_header_qword, vni_mask);

    // Isolate non-contiguous control protocol flags (bits 1, 5, 12, 13)
    uint64_t flag_mask = 0x0000000000003022ULL;
    result.extracted_flags = (uint8_t)_pext_u64(raw_header_qword, flag_mask);

    return result;
}

/**
 * Parallel AVX-512 variation handling byte shuffle lane extractions across a packet block.
 * Treats a 64-byte segment containing continuous fields as parallel elements.
 */
/*
void extract_vni_burst_avx512(const uint8_t *packet_burst_base, uint32_t *out_vnis) {
    // Load unaligned 64 bytes of sequential header elements into a 512-bit ZMM register
    __m512i headers = _mm512_loadu_si512((const __m512i *)packet_burst_base);

    // Byte-shuffle mask matrix to pull targeted bytes (4, 5, 6) into the low slots of 32-bit blocks
    __m512i shuffle_mask = _mm512_setr_epi8(
        4, 5, 6, 0x80,  8, 9, 10, 0x80, 12, 13, 14, 0x80, 16, 17, 18, 0x80,
        20, 21, 22, 0x80, 24, 25, 26, 0x80, 28, 29, 30, 0x80, 32, 33, 34, 0x80,
        36, 37, 38, 0x80, 40, 41, 42, 0x80, 44, 45, 46, 0x80, 48, 49, 50, 0x80,
        52, 53, 54, 0x80, 56, 57, 58, 0x80, 60, 61, 62, 0x80, 64, 65, 66, 0x80
    );

    __m512i shuffled = _mm512_shuffle_epi8(headers, shuffle_mask);

    // Strip remaining noise in the upper byte using a 24-bit filter mask
    __m512i vni_bitmask = _mm512_set1_epi32(0x00FFFFFF);
    __m512i finalized_vnis = _mm512_and_si512(shuffled, vni_bitmask);

    // Stream results cleanly back to the application array bounds
    _mm512_storeu_si512((__m512i *)out_vnis, finalized_vnis);
}
*/

void extract_vni_burst_avx512(const uint8_t *packet_burst_base, uint32_t *out_vnis) {
    // Load unaligned 64 bytes of sequential header elements into a 512-bit ZMM register
    __m512i headers = _mm512_loadu_si512((const __m512i *)packet_burst_base);

    // FIX: Define the 64-byte shuffle mask matrix as a standard array layout
    static const uint8_t __attribute__((aligned(64))) shuffle_mask_bytes[64] = {
        4, 5, 6, 0x80,  8, 9, 10, 0x80, 12, 13, 14, 0x80, 16, 17, 18, 0x80,
        20, 21, 22, 0x80, 24, 25, 26, 0x80, 28, 29, 30, 0x80, 32, 33, 34, 0x80,
        36, 37, 38, 0x80, 40, 41, 42, 0x80, 44, 45, 46, 0x80, 48, 49, 50, 0x80,
        52, 53, 54, 0x80, 56, 57, 58, 0x80, 60, 61, 62, 0x80, 64, 65, 66, 0x80
    };

    // Load the mask from memory into a ZMM register in a single cycle
    __m512i shuffle_mask = _mm512_loadu_si512((const __m512i *)shuffle_mask_bytes);

    // Perform vector execution byte-shuffle
    __m512i shuffled = _mm512_shuffle_epi8(headers, shuffle_mask);

    // Strip remaining noise in the upper byte using a 24-bit filter mask
    __m512i vni_bitmask = _mm512_set1_epi32(0x00FFFFFF);
    __m512i finalized_vnis = _mm512_and_si512(shuffled, vni_bitmask);

    // Stream results cleanly back to the application array bounds
    _mm512_storeu_si512((__m512i *)out_vnis, finalized_vnis);
}

/* ==================================================================================
 * OPERATION 2: VARIABLE-LENGTH HEADER PROFILING VIA SIMD MASK CONVERSION
 * ================================================================================== */

/**
 * Scans 16 distinct network packets in parallel to parse the lower 4 bits of the IHL field.
 * Eliminates routing branches by multiplying the length vector by 4 using logical bitwise shifts.
 */
void compute_l3_offsets_x16(const uint32_t *raw_first_words, uint32_t *out_offsets) {
    // Load 16 parallel 32-bit packet headers simultaneously into the execution matrix
    __m512i first_words = _mm512_loadu_si512((const __m512i *)raw_first_words);

    // Isolate the lowest byte's lower 4 bits (IPv4 Internet Header Length mask value)
    __m512i ihl_mask = _mm512_set1_epi32(0x0000000F);
    __m512i ihl_fields = _mm512_and_si512(first_words, ihl_mask);

    // Multiply IHL by 4 using a logical left shift (<< 2) to resolve total L3 header bytes
    __m512i computed_lengths = _mm512_slli_epi32(ihl_fields, 2);

    // Factor in a static L2 infrastructure baseline value (e.g., standard 14-byte Ethernet framing)
    __m512i baseline_ethernet = _mm512_set1_epi32(14);
    __m512i final_total_offsets = _mm512_add_epi32(computed_lengths, baseline_ethernet);

    _mm512_storeu_si512((__m512i *)out_offsets, final_total_offsets);
}


/* ==================================================================================
 * OPERATION 3: HIGH-PERFORMANCE LOOKUP & VECTOR COMPRESSED BITMAPS
 * ================================================================================== */

/**
 * Evaluates an execution block of 16 packet hashes against a targeted security criteria.
 * Leverages trailing-zero counting loops to isolate matching indexes without linear loops.
 */
uint32_t evaluate_policy_bitmap_lookup(const uint32_t *calculated_hashes, uint32_t target_policy_hash, uint32_t *out_matched_indices) {
    __m512i vector_hashes = _mm512_loadu_si512((const __m512i *)calculated_hashes);
    __m512i target_vector = _mm512_set1_epi32(target_policy_hash);

    // Generate comparison bitmask register mapping
    __mmask16 match_mask = _mm512_cmpeq_epi32_mask(vector_hashes, target_vector);
    uint64_t bit_pipeline_mask = (uint64_t)match_mask;

    uint32_t match_count = 0;

    // Extract set indexes via hardware bit counting logic patterns
    while (bit_pipeline_mask != 0) {
        uint32_t active_index = (uint32_t)_tzcnt_u64(bit_pipeline_mask);
        out_matched_indices[match_count++] = active_index;

        // Clear the processed low bit to shift the execution pipeline context forward
        bit_pipeline_mask &= (bit_pipeline_mask - 1);
    }

    return match_count;
}


/* ==================================================================================
 * OPERATION 4: SYMMETRICAL HASH GENERATION & ENDIANNESS BIT-REVERSALS
 * ================================================================================== */

/**
 * Normalizes 16 pairs of Source/Destination IP contexts into an order-independent layout
 * while converting Big-Endian data formats to Little-Endian structures in a single pass.
 */
/*
void generate_symmetrical_keys_x16(const uint32_t *src_ips, const uint32_t *dst_ips, 
                                   uint32_t *out_symmetrical_keys_low, 
                                   uint32_t *out_symmetrical_keys_high) {
    
    __m512i src_vector = _mm512_loadu_si512((const __m512i *)src_ips);
    __m512i dst_vector = _mm512_loadu_si512((const __m512i *)dst_ips);

    // Compute element-wise min and max paths to force order symmetry: Symmetrical(A, B) == Symmetrical(B, A)
    __m512i low_ips  = _mm512_min_epu32(src_vector, dst_vector);
    __m512i high_ips = _mm512_max_epu32(src_vector, dst_vector);

    // Define standard 4-byte byte inversion mapping rules
    __m512i endian_swap_mask = _mm512_setr_epi8(
        3, 2, 1, 0,  7, 6, 5, 4,  11, 10, 9, 8,  15, 14, 13, 12,
        3, 2, 1, 0,  7, 6, 5, 4,  11, 10, 9, 8,  15, 14, 13, 12,
        3, 2, 1, 0,  7, 6, 5, 4,  11, 10, 9, 8,  15, 14, 13, 12,
        3, 2, 1, 0,  7, 6, 5, 4,  11, 10, 9, 8,  15, 14, 13, 12
    );

    // Execute the vector shuffle to translate wire-level Big Endian numbers into host layouts
    __m512i native_low_ips  = _mm512_shuffle_epi8(low_ips, endian_swap_mask);
    __m512i native_high_ips = _mm512_shuffle_epi8(high_ips, endian_swap_mask);

    _mm512_storeu_si512((__m512i *)out_symmetrical_keys_low, native_low_ips);
    _mm512_storeu_si512((__m512i *)out_symmetrical_keys_high, native_high_ips);
}
*/

void generate_symmetrical_keys_x16(const uint32_t *src_ips, const uint32_t *dst_ips,
                                   uint32_t *out_symmetrical_keys_low,
                                   uint32_t *out_symmetrical_keys_high) {

    __m512i src_vector = _mm512_loadu_si512((const __m512i *)src_ips);
    __m512i dst_vector = _mm512_loadu_si512((const __m512i *)dst_ips);

    // Compute element-wise min and max paths to force order symmetry
    __m512i low_ips  = _mm512_min_epu32(src_vector, dst_vector);
    __m512i high_ips = _mm512_max_epu32(src_vector, dst_vector);

    // FIX: Define the 64-byte byte inversion mapping rules as a static continuous array
    static const uint8_t __attribute__((aligned(64))) endian_swap_mask_bytes[64] = {
        3, 2, 1, 0,  7, 6, 5, 4,  11, 10, 9, 8,  15, 14, 13, 12,
        3, 2, 1, 0,  7, 6, 5, 4,  11, 10, 9, 8,  15, 14, 13, 12,
        3, 2, 1, 0,  7, 6, 5, 4,  11, 10, 9, 8,  15, 14, 13, 12,
        3, 2, 1, 0,  7, 6, 5, 4,  11, 10, 9, 8,  15, 14, 13, 12
    };

    // Load the pre-defined endian matrix allocation from .rodata into a ZMM register in 1 cycle
    __m512i endian_swap_mask = _mm512_loadu_si512((const __m512i *)endian_swap_mask_bytes);

    // Execute the vector shuffle to translate wire-level Big Endian numbers into host layouts
    __m512i native_low_ips  = _mm512_shuffle_epi8(low_ips, endian_swap_mask);
    __m512i native_high_ips = _mm512_shuffle_epi8(high_ips, endian_swap_mask);

    _mm512_storeu_si512((__m512i *)out_symmetrical_keys_low, native_low_ips);
    _mm512_storeu_si512((__m512i *)out_symmetrical_keys_high, native_high_ips);
}


/* ==================================================================================
 * CENTRAL PIPELINE VALIDATION & TESTING DRIVER
 * ================================================================================== */
int main(void) {
    printf("=====================================================================\n");
    printf("ALKIRA VECTORIZED ROUTINE PIPELINE VERIFICATION ENGINE INITIALIZING\n");
    printf("=====================================================================\n\n");

    /* -------------------------------------------------------------------------
     * VALIDATION 1: UNALIGNED BIT EXTRACTION (BMI2 & AVX-512)
     * ------------------------------------------------------------------------- */
    printf("[TEST 1/4] Validating Bit Extraction Realities...\n");
    // Craft a mock pattern: VNI = 0xAABBCC (placed at mask boundaries), Flags active
    uint64_t mock_qword = 0x000000AABBCC3022ULL; 
    parsing_result_t bmi2_out = extract_fields_unaligned_bmi2(mock_qword);
    printf("  -> Scalar BMI2 _pext_u64 Extracted VNI:   0x%X (Expected: 0xAABBCC)\n", bmi2_out.extracted_vni);
    printf("  -> Scalar BMI2 _pext_u64 Extracted Flags: 0x%X (Expected: 0xF)\n", bmi2_out.extracted_flags);

    // Mock an unaligned array block simulating consecutive packet bursts for AVX-512 parsing
    uint8_t __attribute__((aligned(64))) mock_burst_buffer[64];
    memset(mock_burst_buffer, 0, 64);

    for (int i = 0; i < 16; i++) {
	// Inject an easily trackable VNI footprint into the payload window bounds
	mock_burst_buffer[i * 4 + 0] = 0x11 * (i + 1);
	mock_burst_buffer[i * 4 + 1] = 0x22 * (i + 1);
	mock_burst_buffer[i * 4 + 2] = 0x33 * (i + 1);
    }
    uint32_t vectorized_vnis[BURST_SIZE];
    extract_vni_burst_avx512(mock_burst_buffer, vectorized_vnis);
    printf("  -> AVX-512 Vector Burst Lane [0] VNI:     0x%X\n", vectorized_vnis[0]);
    printf("  -> AVX-512 Vector Burst Lane [1] VNI:     0x%X\n", vectorized_vnis[1]);

    /* -------------------------------------------------------------------------
     * VALIDATION 2: VARIABLE L3 HEADER OFFSET PROFILING
     * ------------------------------------------------------------------------- */

    printf("\n[TEST 2/4] Validating L3 Offset Profiling Runtime...\n");
    uint32_t __attribute__((aligned(64))) raw_first_words[BURST_SIZE];
    /* Mix standard IPv4 options parameters across alternating channels (IHL=5 vs IHL=6) */
    for (int i = 0; i < BURST_SIZE; i++) {
        raw_first_words[i] = (i % 2 == 0) ? 0x4500003C : 0x4600003C;
    }
    uint32_t computed_offsets[BURST_SIZE];
    compute_l3_offsets_x16(raw_first_words, computed_offsets);
    printf("  -> Packet Lane [0] Total Egress Offset:   %u bytes (Expected: 54 + 14 = 34)\n", computed_offsets[0]);
    printf("  -> Packet Lane [1] Total Egress Offset:   %u bytes (Expected: 6*4 + 14 = 38)\n", computed_offsets[1]);

    /* -------------------------------------------------------------------------
     * VALIDATION 3: COMPRESSED BITMAP PATH SELECTION
     * ------------------------------------------------------------------------- */

    printf("\n[TEST 3/4] Validating Policy Bitmap Lookup Indexes...\n");
    uint32_t __attribute__((aligned(64))) mock_pipeline_hashes[BURST_SIZE];
    uint32_t target_criteria = 0xDEADC0DE;

    // Force specific indexes to match the policy rule
    for (int i = 0; i < BURST_SIZE; i++) {
        mock_pipeline_hashes[i] = (i == 3 || i == 7 || i == 12) ? target_criteria : 0xAAAAAAAULL;
    }

    uint32_t matched_indices[BURST_SIZE];
    uint32_t total_matches = evaluate_policy_bitmap_lookup(mock_pipeline_hashes, target_criteria, matched_indices);
    printf("  -> Total Hashing Match Hits Detected:     %u (Expected: 3)\n", total_matches);
    for (uint32_t m = 0; m < total_matches; m++) {
        printf("     -> Fast Track Processing Confirmed at Lane Index: %u\n", matched_indices[m]);
    }

    /* -------------------------------------------------------------------------
     * VALIDATION 4: SYMMETRICAL FLOW ORDER SORTING & ENDIAN CORRECTION
     * ------------------------------------------------------------------------- */

     printf("\n[TEST 4/4] Validating Symmetrical Token Bit Reversals...\n");
     uint32_t __attribute__((aligned(64))) src_ip_array[BURST_SIZE];
     uint32_t __attribute__((aligned(64))) dst_ip_array[BURST_SIZE];

     // Scenario Channel 0: Src (10.0.0.1) > Dst (192.168.1.1) in Big Endian configuration
     src_ip_array[0] = 0x0100000A;
     dst_ip_array[0] = 0x0101A8C0;

     // Scenario Channel 1: Src/Dst reversed to verify symmetry optimization rules
     src_ip_array[1] = 0x0101A8C0;
     dst_ip_array[1] = 0x0100000A;

     uint32_t sym_low_out[BURST_SIZE];
     uint32_t sym_high_out[BURST_SIZE];

     generate_symmetrical_keys_x16(src_ip_array, dst_ip_array, sym_low_out, sym_high_out);
     printf("  -> Channel [0] Normalized Low IP Node:    0x%08X | High IP Node: 0x%08X\n", 
		     sym_low_out[0], sym_high_out[0]);

     printf("  -> Channel [1] Normalized Low IP Node:    0x%08X | High IP Node: 0x%08X\n", 
		     sym_low_out[1], sym_high_out[1]);

     if (sym_low_out[0] == sym_low_out[1] && sym_high_out[0] == sym_high_out[1]) {
         printf("  [SUCCESS] Symmetrical Flow Identity verified across independent reverse paths.\n");
     } else {
         printf("  [FAILURE] Polarization Risk detected. Symmetric properties mismatched.\n");
     }

     printf("\n=====================================================================\n");
     printf("ALKIRA VECTOR HARDWARE TEST SUITE PIPELINE EVALUATION COMPLETE\n");
     printf("=====================================================================\n");
     return 0;
}

