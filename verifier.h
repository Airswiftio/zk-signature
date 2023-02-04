#ifdef __cplusplus
extern "C" {
    #endif


#include <stdbool.h>
// Creates and returns proof verifier
int ursa_cl_verifier_new_proof_verifier(void **proof_verifier_p);

// Add a common attribute to the proof verifier
int ursa_cl_proof_verifier_add_common_attribute(void *proof_verifier, char *attribute_name);

int ursa_cl_proof_verifier_add_sub_proof_request(
    void *proof_verifier,
    void *sub_proof_request,
    void *credential_schema,
    void *non_credential_schemad,
    void *credential_pub_key,
    void *rev_key_pub,
    void *rev_reg);

// Verifies proof and deallocates proof verifier.
int ursa_cl_proof_verifier_verify(
    void *proof_verifier,
    void *proof,
    void *nonce,
    bool *valid_p);

#ifdef __cplusplus
}
#endif
