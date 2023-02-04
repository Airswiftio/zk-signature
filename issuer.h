#ifdef __cplusplus
extern "C" {
    #endif


#include <stdbool.h>

// Creates and returns credential definition (public and private keys, correctness proof) entities.
int ursa_cl_issuer_new_credential_def(
    void *credential_schema,
    void *non_credential_schema,
    bool support_revocation,
    void **credential_pub_key_p,
    void **credential_priv_key_p,
    void **credential_key_correctness_proof_p);




// Creates and returns non credential schema builder.



// Credential PublicKey
int ursa_cl_credential_public_key_free(void *credential_pub_key);
int ursa_cl_credential_private_key_free(void *credential_priv_key);
int ursa_cl_credential_key_correctness_proof_free(void *credential_key_correctness_proof);

// Returns json representation of credential public key.
int ursa_cl_credential_public_key_to_json(void *credential_pub_key, char **credential_pub_key_json_p);
int ursa_cl_credential_private_key_to_json(void *credential_priv_key, char **credential_priv_key_json_p);
int ursa_cl_credential_key_correctness_proof_to_json(void *credential_key_correctness_proof, char **credential_key_correctness_proof_json_p);

int ursa_cl_credential_public_key_from_json(char *credential_pub_key_json_py, void **credential_pub_ke);
int ursa_cl_credential_private_key_from_json(char *credential_priv_key_json_p, void **credential_priv_key);
int ursa_cl_credential_key_correctness_proof_from_json(char *credential_key_correctness_proof_json_p, void **credential_key_correctness_proof);

// Creates and returns revocation registry def (public and private keys, correctness proof) entities.
int ursa_cl_issuer_new_revocation_registry_def(void *credential_pub_key,
                                               int max_cred_num,
                                               bool issuance_by_default,
                                               void **rev_key_pub_p,
                                               void **rev_key_priv_p,
                                               void **rev_reg_p,
                                               void **rev_tails_generator_p);

int ursa_cl_revocation_key_public_to_json(void *rev_key_pub_p, char **rev_key_pub_json_p);
int ursa_cl_revocation_key_private_to_json(void *rev_key_priv_p, char **rev_key_priv_json_p);
int ursa_cl_revocation_registry_to_json(void *rev_reg_p, char **rev_reg_json_p);
int ursa_cl_revocation_tails_generator_to_json(void *rev_tails_generator_p, char **rev_tails_generator_json_p);

int ursa_cl_revocation_key_public_from_json(char *rev_key_pub_json_p, void **rev_key_pub_p);
int ursa_cl_revocation_key_private_from_json(char *rev_key_priv_json_p, void **rev_key_priv_p);
int ursa_cl_revocation_registry_from_json(char *rev_reg_json_p, void **rev_reg_p);
int ursa_cl_revocation_tails_generator_from_json(char *rev_tails_generator_json, void **rev_tails_generator_p);

// free
int ursa_cl_revocation_key_public_free(void *rev_key_pub_p);
int ursa_cl_revocation_key_private_free(void *rev_key_priv_p);
int ursa_cl_revocation_registry_free(void *rev_reg_p);
int ursa_cl_revocation_tails_generator_free(void *rev_tails_generator);

// Signs credential values with both primary and revocation keys
typedef int (*FFITailTake)(void *ctx, int idx, void **tail_p);
typedef int (*FFITailPut)(void *ctx, void *tail);



int ursa_cl_issuer_sign_credential_with_revoc(
    char *prover_id,
    void *blinded_credential_secrets,
    void *blinded_credential_secrets_correctness_proof,
    void *credential_nonce,
    void *credential_issuance_nonce,
    void *credential_values,
    void *credential_pub_key,
    void *credential_priv_key,
    int rev_idx,
    int max_cred_num,
    bool issuance_by_default,
    void *rev_reg,
    void *rev_key_priv,
    void *ctx_tails,
    FFITailTake take_tail,
    FFITailPut put_tail,
    void **credential_signature_p,
    void **credential_signature_correctness_proof_p,
    void **revocation_registry_delta_p);

// Signs credential values with primary keys only
int ursa_cl_issuer_sign_credential(
    char *prover_id,
    void *blinded_credential_secrets,
    void *blinded_credential_secrets_correctness_proof,
    void *credential_nonce,
    void *credential_issuance_nonce,
    void *credential_values,
    void *credential_pub_key,
    void *credential_priv_key,
    void **credential_signature_p,
    void **credential_signature_correctness_proof_p);

int ursa_cl_credential_signature_to_json(void *credential_signature, char **credential_signature_json_p);
int ursa_cl_credential_signature_from_json(char *credential_signature_json, void **credential_signature_p);
int ursa_cl_credential_signature_free(void *credential_signature);
int ursa_cl_signature_correctness_proof_to_json(void *signature_correctness_proof, char **signature_correctness_proof_json_p);
int ursa_cl_signature_correctness_proof_from_json(char *signature_correctness_proof_json,
                                                  void **signature_correctness_proof_p);

int ursa_cl_signature_correctness_proof_free(void *signature_correctness_proof);

int ursa_cl_revocation_registry_delta_to_json(
    void *revocation_registry_delta,
    char **revocation_registry_delta_json_p);

int ursa_cl_revocation_registry_delta_from_json(
    char *revocation_registry_delta_json,
    void **revocation_registry_delta_p);

int ursa_cl_revocation_registry_delta_free(void *revocation_registry_delta);

int ursa_revocation_registry_delta_from_parts(void *rev_reg_from,
                                              void *rev_reg_to,
                                              int issued,
                                              int issued_lene,
                                              int revoked,
                                              int revoked_len,
                                              void **rev_reg_delta_p);

int ursa_cl_issuer_revoke_credential(void *rev_reg,
                                     int max_cred_num,
                                     int rev_idx,
                                     void *ctx_tails,
                                     FFITailTake take_taile,
                                     FFITailPut put_tail,
                                     void **rev_reg_delta_p);

//// Recovery a credential by a rev_idx in a given revocation registry
int ursa_cl_issuer_recovery_credential(void *rev_reg,
                                       int max_cred_num,
                                       int rev_idx,
                                       void *ctx_tails,
                                       FFITailTake take_tail,
                                       FFITailPut put_tail,
                                       void **rev_reg_delta_p);

int ursa_cl_issuer_merge_revocation_registry_deltas(void *revoc_reg_delta,
                                                    void *other_revoc_reg_delta,
                                                    void **merged_revoc_reg_delta_p);



int ursa_cl_signature_correctness_proof_to_json(
    void *signature_correctness_proof,
    char **signature_correctness_proof_json_p
);

int ursa_cl_credential_signature_to_json(
    void *credential_signature,
    char **credential_signature_json_p
);

int ursa_cl_revocation_registry_delta_to_json(
    void *revocation_registry_delta,
    char **revocation_registry_delta_json_p
);



#ifdef __cplusplus
}
#endif