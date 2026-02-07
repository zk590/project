


//






//!




use crate::hades::{FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};


#[cfg(feature = "zk")]
pub(crate) mod gadget;


pub(crate) mod scalar;


///




///


pub(crate) trait Hades<T> {
    const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;


    ///


    ///


    fn add_round_constants(
        &mut self,
        round_index: usize,
        state: &mut [T; WIDTH],
    );


    ///



    fn quintic_s_box(&mut self, value: &mut T);


    fn mul_matrix(&mut self, round_index: usize, state: &mut [T; WIDTH]);



    ///






    fn apply_partial_round(
        &mut self,
        round_index: usize,
        state: &mut [T; WIDTH],
    ) {

        self.add_round_constants(round_index, state);


        self.quintic_s_box(&mut state[WIDTH - 1]);


        self.mul_matrix(round_index, state);
    }



    ///






    fn apply_full_round(
        &mut self,
        round_index: usize,
        state: &mut [T; WIDTH],
    ) {

        self.add_round_constants(round_index, state);


        state.iter_mut().for_each(|w| self.quintic_s_box(w));


        self.mul_matrix(round_index, state);
    }


    ///






    ///


    fn perm(&mut self, state: &mut [T; WIDTH]) {

        for full_round_index in 0..FULL_ROUNDS / 2 {
            self.apply_full_round(full_round_index, state);
        }


        for partial_round_index in 0..PARTIAL_ROUNDS {
            self.apply_partial_round(
                partial_round_index + FULL_ROUNDS / 2,
                state,
            );
        }


        for full_round_index in 0..FULL_ROUNDS / 2 {
            self.apply_full_round(
                full_round_index + FULL_ROUNDS / 2 + PARTIAL_ROUNDS,
                state,
            );
        }
    }
}
