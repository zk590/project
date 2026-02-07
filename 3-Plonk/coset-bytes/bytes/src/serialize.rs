
use super::errors::{BadLength, Error};


pub trait Serializable<const N: usize> {

    const SIZE: usize = N;

    type Error;


    fn from_bytes(bytes: &[u8; N]) -> Result<Self, Self::Error>
    where
        Self: Sized;


    fn to_bytes(&self) -> [u8; N];
}






pub trait DeserializableSlice<const N: usize>: Serializable<N> {

    fn from_slice(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: BadLength,
    {
        if bytes.len() < N {
            Err(Self::Error::bad_length(bytes.len(), N))
        } else {
            let mut fixed_bytes = [0u8; N];
            fixed_bytes[..N].copy_from_slice(&bytes[..N]);
            Self::from_bytes(&fixed_bytes)
        }
    }



    fn from_reader<R>(reader: &mut R) -> Result<Self, Self::Error>
    where
        R: Read,
        Self: Sized,
        Self::Error: BadLength,
    {
        let mut fixed_bytes = [0u8; N];
        reader
            .read(&mut fixed_bytes)
            .map_err(|_| Self::Error::bad_length(reader.capacity(), N))?;

        Self::from_bytes(&fixed_bytes)
    }
}



impl<T, const N: usize> DeserializableSlice<N> for T where T: Serializable<N> {}


///

///



pub trait Read {

    fn capacity(&self) -> usize;



    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error>;
}

impl Read for &[u8] {
    #[inline]
    fn capacity(&self) -> usize {
        self.len()
    }

    #[inline]
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, Error> {
        if buffer.len() > self.len() {
            return Err(Error::bad_length(self.len(), buffer.len()));
        }
        let bytes_to_read = buffer.len();
        let (head, tail) = self.split_at(bytes_to_read);




        if bytes_to_read == 1 {
            buffer[0] = head[0];
        } else {
            buffer[..bytes_to_read].copy_from_slice(head);
        }

        *self = tail;
        Ok(bytes_to_read)
    }
}


///

///

pub trait Write {

    ///



    fn write(&mut self, bytes: &[u8]) -> Result<usize, Error>;
}

impl Write for &mut [u8] {
    #[inline]
    fn write(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        if bytes.len() > self.len() {
            return Err(Error::bad_length(self.len(), bytes.len()));
        }
        let bytes_to_write = bytes.len();

        let (head, tail) = core::mem::take(self).split_at_mut(bytes_to_write);
        head.copy_from_slice(&bytes[..bytes_to_write]);
        *self = tail;
        Ok(bytes_to_write)
    }
}
