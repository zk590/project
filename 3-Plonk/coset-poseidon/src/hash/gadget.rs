


//


use alloc::vec::Vec;

use plonk::prelude::{Composer, Witness};
use dusk_safe::Sponge;

use crate::hades::GadgetPermutation;
use crate::Domain;

use super::build_io_pattern;


pub struct HashGadget<'a> {
    domain: Domain,
    input: Vec<&'a [Witness]>,
    output_len: usize,
}

impl<'a> HashGadget<'a> {

    pub fn new(domain: Domain) -> Self {
        Self {
            domain,
            input: Vec::new(),
            output_len: 1,
        }
    }




    pub fn output_len(&mut self, output_len: usize) {
        if self.domain == Domain::Other && output_len > 0 {
            self.output_len = output_len;
        }
    }


    pub fn update(&mut self, input: &'a [Witness]) {
        self.input.push(input);
    }


    ///




    pub fn finalize(&self, composer: &mut Composer) -> Vec<Witness> {


        let mut poseidon_sponge = Sponge::start(
            GadgetPermutation::new(composer),
            build_io_pattern(self.domain, &self.input, self.output_len)
                .expect("io-pattern should be valid"),
            self.domain.into(),
        )
        .expect("at this point the io-pattern is valid");


        for segment in self.input.iter() {
            poseidon_sponge
                .absorb(segment.len(), segment)
                .expect("at this point the io-pattern is valid");
        }


        poseidon_sponge
            .squeeze(self.output_len)
            .expect("at this point the io-pattern is valid");


        poseidon_sponge
            .finish()
            .expect("at this point the io-pattern is valid")
    }


    ///




    pub fn finalize_truncated(&self, composer: &mut Composer) -> Vec<Witness> {

        let field_witnesses = self.finalize(composer);


        field_witnesses
            .iter()
            .map(|witness| {
                composer.append_logic_xor::<125>(*witness, Composer::ZERO)
            })
            .collect()
    }


    ///




    pub fn digest(
        composer: &mut Composer,
        domain: Domain,
        input: &'a [Witness],
    ) -> Vec<Witness> {
        let mut poseidon_hash = Self::new(domain);
        poseidon_hash.update(input);
        poseidon_hash.finalize(composer)
    }


    ///




    pub fn digest_truncated(
        composer: &mut Composer,
        domain: Domain,
        input: &'a [Witness],
    ) -> Vec<Witness> {
        let mut poseidon_hash = Self::new(domain);
        poseidon_hash.update(input);
        poseidon_hash.finalize_truncated(composer)
    }
}
