fn main() {
    zkm_build::build_program("../guest");
    zkm_build::build_program("../../fibonacci_add/guest");
    zkm_build::build_program("../../fibonacci_mul/guest");
    zkm_build::build_program("../../sha2/guest");
    zkm_build::build_program("../../sha3/guest");
}
