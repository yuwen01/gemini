//! Dummy streams used mostly for testing purposes.
use core::marker::PhantomData;

use ark_ff::{PrimeField, Zero};
use ark_std::vec::Vec;
use ark_std::{iter, rand::RngCore};

use crate::{circuit::R1csStream, iterable::Iterable, misc::MatrixElement};

/// A DummyStream is the stream that returns the same element `e`, `len` times.
#[derive(Clone, Copy)]
pub struct DummyStreamer<T> {
    e: T,
    len: usize,
}

impl<T: Copy> DummyStreamer<T> {
    /// Creates new stream that will repeat `len` times the same element `e`.
    pub fn new(e: T, len: usize) -> Self {
        Self { e, len }
    }
}

/// Dummy stream for the diagonal matrix.
#[derive(Clone, Copy)]
pub struct DiagonalMatrixStreamer<T> {
    e: T,
    len: usize,
}

#[derive(Copy, Clone)]
pub struct RepeatStreamer<'a, T>
where
    T: Send + Sync,
{
    m: &'a [T],
    repeat: usize,
}

impl<'a, T> Iterable for RepeatStreamer<'a, T>
where
    T: Send + Sync,
{
    type Item = &'a T;

    type Iter = iter::Take<iter::Cycle<ark_std::slice::Iter<'a, T>>>;

    fn iter(&self) -> Self::Iter {
        self.m.iter().cycle().take(self.len())
    }

    fn len(&self) -> usize {
        self.m.len() * self.repeat
    }
}

impl<'a, T> RepeatStreamer<'a, T>
where
    T: Send + Sync,
{
    pub fn new(m: &'a [T], repeat: usize) -> Self {
        Self { m, repeat }
    }
}

#[derive(Copy, Clone)]
pub struct ConcatStreamer<'a, T>
where
    T: Send + Sync,
{
    m: &'a Vec<Vec<T>>,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> Iterable for ConcatStreamer<'a, T>
where
    T: Send + Sync,
{
    type Item = &'a T;

    type Iter = ConcatIterator<'a, T>;

    fn iter(&self) -> Self::Iter {
        Self::Iter {
            m: self.m,
            row: 0,
            col: 0,
            phantom: PhantomData,
        }
    }

    fn len(&self) -> usize {
        self.m.iter().fold(0, |a, b| a + (*b).len())
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a, T> ConcatStreamer<'a, T>
where
    T: Send + Sync,
{
    pub fn new(m: &'a Vec<Vec<T>>) -> Self {
        Self {
            m,
            phantom: PhantomData,
        }
    }
}

pub struct ConcatIterator<'a, T> {
    m: &'a Vec<Vec<T>>,
    row: usize,
    col: usize,
    phantom: PhantomData<&'a T>,
}

impl<'a, T> Iterator for ConcatIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.row >= self.m.len() {
            None
        } else {
            let cur_row = &self.m[self.row];
            if self.col >= cur_row.len() {
                self.col = 0;
                self.row += 1;
                self.next()
            } else {
                self.col += 1;
                Some(&cur_row[self.col - 1])
            }
        }
    }
}

#[derive(Clone)]
pub struct RepeatMatrixStreamer<T> {
    m: Vec<T>,
    repeat: usize,
    block_size: usize,
}

impl<T> Iterable for RepeatMatrixStreamer<MatrixElement<T>>
where
    T: Send + Sync + Copy,
{
    type Item = MatrixElement<T>;

    type Iter = RepeatMatrixIterator<T>;

    fn iter(&self) -> Self::Iter {
        Self::Iter {
            m: self.m.clone(),
            repeat: self.repeat,
            block_size: self.block_size,
            count: 0,
        }
    }

    fn len(&self) -> usize {
        self.m.len() * self.repeat
    }
}

impl<T: Clone> RepeatMatrixStreamer<MatrixElement<T>> {
    pub fn new(m: Vec<MatrixElement<T>>, repeat: usize, block_size: usize) -> Self {
        Self {
            m,
            repeat,
            block_size,
        }
    }
}
pub struct RepeatMatrixIterator<T> {
    m: Vec<MatrixElement<T>>,
    repeat: usize,
    count: usize,
    block_size: usize,
}

impl<T: Copy> Iterator for RepeatMatrixIterator<T> {
    type Item = MatrixElement<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 && self.repeat == 0 {
            None
        } else {
            if self.repeat != 0 && self.count == 0 {
                self.count = self.m.len();
                self.repeat -= 1;
            }
            self.count -= 1;
            match self.m[self.count] {
                MatrixElement::Element((e, i)) => Some(MatrixElement::Element((
                    e,
                    i + self.repeat * self.block_size,
                ))),
                t => Some(t),
            }
        }
    }
}

/// Iterator for the diagonal matrix.
pub struct DiagonalMatrixIter<T> {
    e: T,
    len: usize,
}

/// A dummy stream with only a single element.
#[derive(Clone, Copy)]
pub struct SingleEntryStream<T> {
    e: T,
    len: usize,
}

impl<T> Iterable for SingleEntryStream<T>
where
    T: Copy + Zero + Send + Sync,
{
    type Item = T;
    type Iter = iter::Chain<iter::Take<iter::Repeat<T>>, iter::Take<iter::Repeat<T>>>;

    fn len(&self) -> usize {
        self.len
    }
    fn iter(&self) -> Self::Iter {
        iter::repeat(T::zero())
            .take(self.len - 1)
            .chain(iter::repeat(self.e).take(1))
    }
}
impl<T: Copy> DiagonalMatrixStreamer<T> {
    /// Creates new stream that will repeat `len` times the same element `e`.
    pub fn new(e: T, len: usize) -> Self {
        Self { e, len }
    }
}

impl<T: PrimeField> Iterable for DiagonalMatrixStreamer<T> {
    type Item = MatrixElement<T>;
    type Iter = DiagonalMatrixIter<T>;

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn iter(&self) -> Self::Iter {
        DiagonalMatrixIter {
            e: self.e,
            len: self.len * 2,
        }
    }
}

impl<T: PrimeField> Iterator for DiagonalMatrixIter<T> {
    type Item = MatrixElement<T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            None
        } else if self.len % 2 == 1 {
            self.len -= 1;
            Some(MatrixElement::EOL)
        } else {
            self.len -= 1;
            Some(MatrixElement::Element((self.e, self.len >> 1)))
        }
    }
}

impl<T> Iterable for DummyStreamer<T>
where
    T: Send + Sync + Copy,
{
    type Item = T;
    type Iter = iter::Take<iter::Repeat<T>>;

    fn iter(&self) -> Self::Iter {
        iter::repeat(self.e).take(self.len)
    }

    fn len(&self) -> usize {
        self.len
    }
}

type DummyR1CStream<F> = R1csStream<DiagonalMatrixStreamer<F>, DummyStreamer<F>, DummyStreamer<F>>;

/// Output a stream for the dummy R1CS instance.
pub fn dummy_r1cs_stream<F: PrimeField, R: RngCore>(rng: &mut R, n: usize) -> DummyR1CStream<F> {
    let e = F::rand(rng);
    let inv_e = e.inverse().expect("Buy a lottery ticket and retry");
    R1csStream {
        a_colmaj: DiagonalMatrixStreamer::new(inv_e, n),
        b_colmaj: DiagonalMatrixStreamer::new(inv_e, n),
        c_colmaj: DiagonalMatrixStreamer::new(inv_e, n),
        a_rowmaj: DiagonalMatrixStreamer::new(inv_e, n),
        b_rowmaj: DiagonalMatrixStreamer::new(inv_e, n),
        c_rowmaj: DiagonalMatrixStreamer::new(inv_e, n),
        witness: DummyStreamer::new(e, n - 1),
        z: DummyStreamer::new(e, n),
        z_a: DummyStreamer::new(F::one(), n),
        z_b: DummyStreamer::new(F::one(), n),
        z_c: DummyStreamer::new(F::one(), n),
        nonzero: n,
        joint_len: n,
    }
}

#[test]
fn test_dummy_streamer() {
    let e = 1;
    let dummy = DummyStreamer::new(e, 1);
    let mut stream = dummy.iter();

    assert_eq!(stream.next(), Some(1));
    assert_eq!(stream.next(), None);
}

#[test]
fn test_dummy_matrix_streamer() {
    use ark_ff::One;
    use ark_test_curves::bls12_381::Fr;
    type F = Fr;

    let e = F::one();
    let dummy = DiagonalMatrixStreamer::new(e, 2);
    let mut stream = dummy.iter();

    assert_eq!(stream.next(), Some(MatrixElement::Element((e, 1))));
    assert_eq!(stream.next(), Some(MatrixElement::EOL));
    assert_eq!(stream.next(), Some(MatrixElement::Element((e, 0))));
    assert_eq!(stream.next(), Some(MatrixElement::EOL));
}

#[derive(Clone, Copy)]
pub struct Mat<S>(pub S, pub usize);

impl<S> Iterable for Mat<S>
where
    S: Iterable,
{
    type Item = S::Item;

    type Iter = S::Iter;

    fn iter(&self) -> Self::Iter {
        self.0.iter()
    }

    fn len(&self) -> usize {
        self.1
    }
}
