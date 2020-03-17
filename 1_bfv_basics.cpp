// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_bfv_basics()
{
    print_example_banner("Example: BFV Basics");

    EncryptionParameters parms(scheme_type::BFV);

    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);

    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));

    parms.set_plain_modulus(1024);

    random_seed_type seed;
    for (auto &i: seed)
    {
	i = random_uint64();
    }
    auto rng = make_shared<BlakePRNGFactory>(BlakePRNGFactory(seed));
    parms.set_random_generator(rng);

    auto context = SEALContext::Create(parms);

    print_line(__LINE__);
    cout << "Set encryption parameters and print" << endl;
    print_parameters(context);

    cout << endl;
    cout << "~~~~~~ A naive way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

    KeyGenerator keygen(context);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();

    Encryptor encryptor(context, public_key);

    Evaluator evaluator(context);

    Decryptor decryptor(context, secret_key);

    int x = 6;
    Plaintext x_plain(to_string(x));
    Ciphertext x_encrypted;
    encryptor.encrypt(x_plain, x_encrypted);

    Plaintext plain_one("1");
    Plaintext plain_four("4");
    Ciphertext x_sq_plus_one;
    Plaintext decrypted_result;
    Ciphertext encrypted_result;
    Ciphertext x_plus_one_sq;



    cout << endl;
    cout << "~~~~~~ A better way to calculate 4(x^2+1)(x+1)^2. ~~~~~~" << endl;

    print_line(__LINE__);
    cout << "Generate relinearization keys." << endl;
    auto relin_keys = keygen.relin_keys();

    /*
    We now repeat the computation relinearizing after each multiplication.
    */
    print_line(__LINE__);
    cout << "Compute and relinearize x_squared (x^2)," << endl;
    cout << string(13, ' ') << "then compute x_sq_plus_one (x^2+1)" << endl;
    Ciphertext x_squared;
    evaluator.square(x_encrypted, x_squared);
    cout << "    + size of x_squared: " << x_squared.size() << endl;
    evaluator.relinearize_inplace(x_squared, relin_keys);
    cout << "    + size of x_squared (after relinearization): "
        << x_squared.size() << endl;
    evaluator.add_plain(x_squared, plain_one, x_sq_plus_one);
    cout << "    + noise budget in x_sq_plus_one: "
        << decryptor.invariant_noise_budget(x_sq_plus_one) << " bits" << endl;
    cout << "    + decryption of x_sq_plus_one: ";
    decryptor.decrypt(x_sq_plus_one, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    print_line(__LINE__);
    Ciphertext x_plus_one;
    cout << "Compute x_plus_one (x+1)," << endl;
    cout << string(13, ' ')
        << "then compute and relinearize x_plus_one_sq ((x+1)^2)." << endl;
    evaluator.add_plain(x_encrypted, plain_one, x_plus_one);
    evaluator.square(x_plus_one, x_plus_one_sq);
    cout << "    + size of x_plus_one_sq: " << x_plus_one_sq.size() << endl;
    evaluator.relinearize_inplace(x_plus_one_sq, relin_keys);
    cout << "    + noise budget in x_plus_one_sq: "
        << decryptor.invariant_noise_budget(x_plus_one_sq) << " bits" << endl;
    cout << "    + decryption of x_plus_one_sq: ";
    decryptor.decrypt(x_plus_one_sq, decrypted_result);
    cout << "0x" << decrypted_result.to_string() << " ...... Correct." << endl;

    print_line(__LINE__);
    cout << "Compute and relinearize encrypted_result (4(x^2+1)(x+1)^2)." << endl;
    evaluator.multiply_plain_inplace(x_sq_plus_one, plain_four);
    evaluator.multiply(x_sq_plus_one, x_plus_one_sq, encrypted_result);
    cout << "    + size of encrypted_result: " << encrypted_result.size() << endl;
    evaluator.relinearize_inplace(encrypted_result, relin_keys);
    cout << "    + size of encrypted_result (after relinearization): "
        << encrypted_result.size() << endl;
    cout << "    + noise budget in encrypted_result: "
        << decryptor.invariant_noise_budget(encrypted_result) << " bits" << endl;

    cout << endl;
    cout << "NOTE: Notice the increase in remaining noise budget." << endl;

    print_line(__LINE__);
    cout << "Decrypt encrypted_result (4(x^2+1)(x+1)^2)." << endl;
    decryptor.decrypt(encrypted_result, decrypted_result);
    cout << "    + decryption of 4(x^2+1)(x+1)^2 = 0x"
        << decrypted_result.to_string() << " ...... Correct." << endl;
    cout << endl;

    /*
    For x=6, 4(x^2+1)(x+1)^2 = 7252. Since the plaintext modulus is set to 1024,
    this result is computed in integers modulo 1024. Therefore the expected output
    should be 7252 % 1024 == 84, or 0x54 in hexadecimal.
    */
}
