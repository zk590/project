
use crate::{init_fixed_array, Aggregate, Node, Tree};

use alloc::vec::Vec;

#[cfg(feature = "rkyv-impl")]
use bytecheck::CheckBytes;
use coset_bytes::{DeserializableSlice, Error as BytesError, Serializable};
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};


#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(CheckBytes))
)]
pub struct Opening<T, const H: usize, const A: usize> {
    root: T,
    branch: [[T; A]; H],
    positions: [usize; H],
}

impl<T, const H: usize, const A: usize> Opening<T, H, A>
where
    T: Aggregate<A> + Clone,
{


    /// 基于树和目标位置构造 opening。
    pub(crate) fn new(tree: &Tree<T, H, A>, position: u64) -> Self {
        let opening_positions = [0; H];
        let opening_branch =
            init_fixed_array(|_| init_fixed_array(|_| T::EMPTY_SUBTREE));

        let mut opening = Self {
            root: tree.root.aggregated_item().clone(),
            branch: opening_branch,
            positions: opening_positions,
        };
        populate_opening_path(&mut opening, &tree.root, 0, position);

        opening
    }


    /// 返回 opening 对应的根值。
    pub fn root(&self) -> &T {
        &self.root
    }


    /// 返回每一层的分支节点值。
    pub fn branch(&self) -> &[[T; A]; H] {
        &self.branch
    }


    /// 返回每一层路径中的子索引。
    pub fn positions(&self) -> &[usize; H] {
        &self.positions
    }



    /// 校验给定叶子是否匹配该 opening。
    pub fn verify(&self, item: impl Into<T>) -> bool
    where
        T: PartialEq,
    {
        let mut item = item.into();

        for level_index in (0..H).rev() {
            let level_branch = &self.branch[level_index];
            let level_position = self.positions[level_index];



            if item != level_branch[level_position] {
                return false;
            }

            let empty_subtree = &T::EMPTY_SUBTREE;

            let mut item_refs = [empty_subtree; A];
            item_refs.iter_mut().zip(level_branch).for_each(
                |(r, item_ref)| {
                    *r = item_ref;
                },
            );

            item = T::aggregate(item_refs);
        }

        self.root == item
    }





    /// 将 opening 编码为变长字节串。
    pub fn to_var_bytes<const T_SIZE: usize>(&self) -> Vec<u8>
    where
        T: Serializable<T_SIZE>,
    {
        let mut bytes = Vec::with_capacity(
            (1 + H * A) * T_SIZE + H * (u32::BITS as usize / 8),
        );


        bytes.extend(&self.root.to_bytes());


        for level in &self.branch {
            for item in level {
                bytes.extend(&item.to_bytes());
            }
        }


        for position_index in self.positions {


            #[allow(clippy::cast_possible_truncation)]
            bytes.extend(&(position_index as u32).to_bytes());
        }

        bytes
    }


    /// 从字节切片解码 opening，并校验长度。
    pub fn from_slice<const T_SIZE: usize>(
        bytes: &[u8],
    ) -> Result<Self, BytesError>
    where
        T: Serializable<T_SIZE>,
        <T as Serializable<T_SIZE>>::Error: coset_bytes::BadLength,
        coset_bytes::Error: From<<T as Serializable<T_SIZE>>::Error>,
    {
        let expected_len = (1 + H * A) * T_SIZE + H * (u32::BITS as usize / 8);
        if bytes.len() != expected_len {
            return Err(BytesError::BadLength {
                found: (bytes.len()),
                expected: (expected_len),
            });
        }

        let mut reader = bytes;


        let root = T::from_reader(&mut reader)?;


        let mut branch: [[T; A]; H] =
            init_fixed_array(|_| init_fixed_array(|_| T::EMPTY_SUBTREE));
        for level in &mut branch {
            for item in &mut *level {
                *item = T::from_reader(&mut reader)?;
            }
        }


        let mut positions = [0usize; H];
        for position_slot in &mut positions {
            *position_slot = u32::from_reader(&mut reader)? as usize;
        }

        Ok(Self {
            root,
            branch,
            positions,
        })
    }
}

/// 递归填充 opening 的分支与路径信息。
fn populate_opening_path<T, const H: usize, const A: usize>(
    opening: &mut Opening<T, H, A>,
    node: &Node<T, H, A>,
    height: usize,
    position: u64,
) where
    T: Aggregate<A> + Clone,
{
    if height == H {
        return;
    }

    let (child_index, child_position) =
        Node::<T, H, A>::child_index_and_offset(height, position);
    let child = node.children[child_index]
        .as_ref()
        .expect("There should be a child at this position");

    populate_opening_path(opening, child, height + 1, child_position);

    for child_index in 0..A {
        if let Some(child) = &node.children[child_index] {
            opening.branch[height][child_index] =
                child.aggregated_item().clone();
        }
    }
    opening.positions[height] = child_index;
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: usize = 4;
    const A: usize = 2;
    const TREE_CAP: usize = A.pow(H as u32);



    #[derive(Clone, Copy, PartialEq)]
    struct String {
        chars: [char; TREE_CAP],
        len: usize,
    }

    impl From<char> for String {
        fn from(c: char) -> Self {
            let mut chars = ['0'; TREE_CAP];
            chars[0] = c;
            Self { chars, len: 1 }
        }
    }

    const EMPTY_ITEM: String = String {
        chars: ['0'; TREE_CAP],
        len: 0,
    };


    impl Aggregate<A> for String {
        const EMPTY_SUBTREE: Self = EMPTY_ITEM;

        fn aggregate(items: [&Self; A]) -> Self {
            items.into_iter().fold(EMPTY_ITEM, |mut acc, s| {
                acc.chars[acc.len..acc.len + s.len]
                    .copy_from_slice(&s.chars[..s.len]);
                acc.len += s.len;
                acc
            })
        }
    }

    type TestTree = Tree<String, H, A>;

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn opening_verify() {
        const LETTERS: &[char] = &[
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P',
        ];

        let mut tree = TestTree::new();
        let cap = tree.capacity();

        for i in 0..cap {
            tree.insert(i, LETTERS[i as usize]);
        }

        for pos in 0..cap {
            let opening = tree
                .opening(pos)
                .expect("There must be an opening for an existing item");

            assert!(
                opening.verify(LETTERS[pos as usize]),
                "The opening should be for the item that was inserted at the given position"
            );

            assert!(
                !opening.verify(LETTERS[((pos + 1)%cap) as usize]),
                "The opening should *only* be for the item that was inserted at the given position"
            );
        }
    }
}
