#ifdef __cplusplus
extern "C" {
    #endif
#include "vector.h"

typedef int (*FFITailTake)(void *ctx, int idx, void **tail_p);
typedef int (*FFITailPut)(void *ctx, void *tail);

int ursa_cl_credential_values_builder_new(void **credential_values_builder_p);

int ursa_cl_credential_values_builder_finalize(void *credential_values_builder, void **credential_values_p);
// Creates random nonce.
//* `nonce_p` - Reference that will contain nonce instance pointer.
int ursa_cl_new_nonce(void **nonce_p);

int ursa_cl_tails_generator_count(void *rev_tails_generator, int *count_p);

int ursa_cl_tails_generator_next(void *rev_tails_generator, void **tail_p);

int ursa_cl_tail_free(void *tail);

int ursa_cl_witness_new(
    int rev_idx,
    int max_cred_num,
    bool issuance_by_default,
    void *rev_reg_delta,
    void *ctx_tails,
    FFITailTake take_tail,
    FFITailPut put_tail,
    void **witness_p
);

int ursa_cl_witness_update(
    int rev_idx,
    int max_cred_num,
    void *rev_reg_delta,
    void *witness,
    void *ctx_tails,
    FFITailTake take_tail,
    FFITailPut put_tail
);

int ursa_cl_witness_free(void *witness);

// Creates and returns credential schema entity builder.
int ursa_cl_credential_schema_builder_new(void **credential_schema_builder);

int ursa_cl_credential_values_builder_add_dec_hidden(
    void *credential_values_builder,
    char *attr,
    char *dec_valuer);

int ursa_cl_credential_schema_builder_add_attr(void *credential_schema_builder, char *attr);
int ursa_cl_credential_schema_builder_finalize(void *credential_schema_builder, void **credential_schema_builder_p);
int ursa_cl_credential_schema_free(void *credential_schema);

int ursa_cl_non_credential_schema_builder_new(void **non_credential_schema_builder);
int ursa_cl_non_credential_schema_builder_add_attr(void *non_credential_schema_builder, char *attr);

int ursa_cl_non_credential_schema_builder_finalize(void *ursa_cl_non_credential_schema_builder_finalize, void **non_credential_schema_p);
int ursa_cl_non_credential_schema_free(void *non_credential_schema);

int _free_non_credential_schema_builder(void *non_credential_schema_builder);

int ursa_cl_credential_values_to_json(
    void *credential_values,
    char **credential_values_json_p);

int ursa_cl_credential_values_from_json(
    char *credential_values_json,
    void **credential_values_p
);

int ursa_cl_sub_proof_request_builder_new(void **sub_proof_request_builder_p);

int  ursa_cl_credential_values_builder_add_dec_known(
    void *credential_values_builder,
    char *attr,
    char *dec_value
);
int ursa_cl_sub_proof_request_builder_add_revealed_attr(void *sub_proof_request_builder, char *attr);
int ursa_cl_sub_proof_request_builder_add_predicate(
    void *sub_proof_request_builder,
    char *attr_name,
    char *p_type,
    int value);

int ursa_cl_credential_values_builder_add_dec_commitment(
    void *credential_values_builder,
    char *attr,
    char *dec_value,
    char *dec_blinding_factor
);

int ursa_cl_sub_proof_request_builder_finalize(
    void *sub_proof_request_builder,
    void **sub_proof_request_P);

int ursa_cl_nonce_to_json(
    void *nonce,
    char **nonce_json_p
);

int ursa_cl_nonce_from_json(
    char *nonce_json,
    void **nonce_p
);

int ursa_cl_credential_values_free(void *credential_values);
int ursa_cl_nonce_free(void *nonce);

int ursa_cl_sub_proof_request_free(void *sub_proof_request);

enum 
{
    Success = 0,

    // Common errors

    // Caller passed invalid value as param 1 (null, invalid json and etc..)
    CommonInvalidParam1 = 100,

    // Caller passed invalid value as param 2 (null, invalid json and etc..)
    CommonInvalidParam2 = 101,

    // Caller passed invalid value as param 3 (null, invalid json and etc..)
    CommonInvalidParam3 = 102,

    // Caller passed invalid value as param 4 (null, invalid json and etc..)
    CommonInvalidParam4 = 103,

    // Caller passed invalid value as param 5 (null, invalid json and etc..)
    CommonInvalidParam5 = 104,

    // Caller passed invalid value as param 6 (null, invalid json and etc..)
    CommonInvalidParam6 = 105,

    // Caller passed invalid value as param 7 (null, invalid json and etc..)
    CommonInvalidParam7 = 106,

    // Caller passed invalid value as param 8 (null, invalid json and etc..)
    CommonInvalidParam8 = 107,

    // Caller passed invalid value as param 9 (null, invalid json and etc..)
    CommonInvalidParam9 = 108,

    // Caller passed invalid value as param 10 (null, invalid json and etc..)
    CommonInvalidParam10 = 109,

    // Caller passed invalid value as param 11 (null, invalid json and etc..)
    CommonInvalidParam11 = 110,

    // Caller passed invalid value as param 11 (null, invalid json and etc..)
    CommonInvalidParam12 = 111,

    // Invalid library state was detected in runtime. It signals library bug
    CommonInvalidState = 112,

    // Object (json, config, key, credential and etc...) passed by library caller has invalid structure
    CommonInvalidStructure = 113,

    // IO Error
    CommonIOError = 114,

    // Trying to issue non-revocation credential with full anoncreds revocation accumulator
    AnoncredsRevocationAccumulatorIsFull = 115,

    // Invalid revocation accumulator index
    AnoncredsInvalidRevocationAccumulatorIndex = 116,

    // Credential revoked
    AnoncredsCredentialRevoked = 117,

    // Proof rejected
    AnoncredsProofRejected = 118,
} static ErrorCode;



// int new_tail(void *rev_tails_generator, Vector *tail_storage)
// {
//     int cnt = 0;
//     ursa_cl_tails_generator_count(rev_tails_generator, &cnt);
//     int i;
//     for (i = 0; i < cnt; i++)
//     {
//         void *tail_p = NULL;
//         ursa_cl_tails_generator_next(rev_tails_generator, &tail_p);
//         vector_push_back(tail_storage, tail_p);
//     }
    
//     return Success;
// }

// int tail_put(Vector *tail_storge, void *tail)
// {
//     return Success;
// }

// int tail_take(Vector *tail_storge, int idx, void **tail_p)
// {  
//     *tail_p = vector_get(tail_storge, idx);
//     return Success;
// }


#ifdef __cplusplus
}
#endif