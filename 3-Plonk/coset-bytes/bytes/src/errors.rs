



pub trait BadLength {

    fn bad_length(found: usize, expected: usize) -> Self;
}





pub trait InvalidChar {


    fn invalid_char(ch: char, index: usize) -> Self;
}


#[derive(Copy, Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Error {


    InvalidData,



    BadLength {

        found: usize,

        expected: usize,
    },



    InvalidChar {

        ch: char,

        index: usize,
    },
}

impl BadLength for Error {
    fn bad_length(found: usize, expected: usize) -> Self {
        Self::BadLength { found, expected }
    }
}

impl InvalidChar for Error {
    fn invalid_char(ch: char, index: usize) -> Self {
        Self::InvalidChar { ch, index }
    }
}
