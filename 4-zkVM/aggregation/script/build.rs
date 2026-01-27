fn main() {
    sp1_build::build_program("../program");
    sp1_build::build_program("../../fibonacci_add/program");
    sp1_build::build_program("../../sha2/program");
    sp1_build::build_program("../../coset/program");
    sp1_build::build_program("../../keccak/program");
    sp1_build::build_program("../../rsa/program");
    sp1_build::build_program("../../schnorr/program");
    sp1_build::build_program("../../fibonacci_mul/program");
    sp1_build::build_program("../../ecdsa/program");
    sp1_build::build_program("../../sha3/program");
}