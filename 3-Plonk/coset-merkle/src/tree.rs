
use alloc::collections::BTreeSet;
use core::cell::Ref;

use crate::{level_capacity, Aggregate, Node, Opening, Walk};


#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Tree<T, const H: usize, const A: usize> {
    pub(crate) root: Node<T, H, A>,
    positions: BTreeSet<u64>,
}

impl<T, const H: usize, const A: usize> Default for Tree<T, H, A>
where
    T: Aggregate<A>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const H: usize, const A: usize> Tree<T, H, A>
where
    T: Aggregate<A>,
{

    #[must_use]
    /// 创建一棵空的 Merkle 树。
    pub const fn new() -> Self {
        Self {
            root: Node::new(),
            positions: BTreeSet::new(),
        }
    }

    /// 在指定叶子位置插入（或覆盖）一个元素，并向上更新聚合值。
    pub fn insert(&mut self, index: u64, item: impl Into<T>) {
        let capacity = self.capacity();

        assert!(
            index < capacity,
            "index out of bounds: \
             the capacity is {capacity} but the index is {index}"
        );

        self.root.insert(0, index, item);
        self.positions.insert(index);
    }


    /// 移除指定位置的叶子元素；若位置不存在则返回 `None`。
    pub fn remove(&mut self, position: u64) -> Option<T> {
        if !self.positions.contains(&position) {
            return None;
        }

        let (item, _) = self.root.remove(0, position);
        self.positions.remove(&position);

        Some(item)
    }

    /// 为指定位置生成开证明（Opening）。
    pub fn opening(&self, position: u64) -> Option<Opening<T, H, A>>
    where
        T: Clone,
    {
        if !self.positions.contains(&position) {
            return None;
        }
        Some(Opening::new(self, position))
    }

    /// 按给定谓词遍历树中叶子，返回惰性迭代器。
    pub fn walk<W>(&self, walker: W) -> Walk<'_, T, W, H, A>
    where
        W: Fn(&T) -> bool,
    {
        Walk::new(self, walker)
    }

    /// 返回当前根节点聚合值。
    pub fn root(&self) -> Ref<'_, T> {
        self.root.aggregated_item()
    }

    /// 返回覆盖全部已插入元素的最小子树及其高度。
    pub fn smallest_subtree(&self) -> (Ref<'_, T>, usize) {
        let mut current_node = &self.root;
        let mut current_height = H;
        loop {
            let mut non_empty_children =
                current_node.children.iter().flatten();
            match non_empty_children.next() {



                None => return (self.root(), 0),
                Some(child) => {


                    if non_empty_children.next().is_none()
                        && current_height > 1
                    {
                        current_node = child;
                    }



                    else {
                        return (current_node.aggregated_item(), current_height);
                    }
                }
            }
            current_height -= 1;
        }
    }

    /// 判断某个位置是否已有元素。
    pub fn contains(&self, position: u64) -> bool {
        self.positions.contains(&position)
    }

    /// 返回当前已插入叶子数量。
    #[must_use]
    pub fn len(&self) -> u64 {
        self.positions.len() as u64
    }

    /// 判断树是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 返回该树在当前高度和分叉度下的容量。
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        level_capacity(A as u64, H)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl Aggregate<A> for u8 {
        const EMPTY_SUBTREE: Self = 0;

        fn aggregate(items: [&Self; A]) -> Self {
            items.into_iter().sum()
        }
    }

    const H: usize = 3;
    const A: usize = 2;

    type SumTree = Tree<u8, H, A>;

    #[test]
    fn tree_insertion() {
        let mut tree = SumTree::new();

        tree.insert(5, 42);
        tree.insert(6, 42);
        tree.insert(5, 42);

        assert_eq!(
            tree.len(),
            2,
            "Three items were inserted, but one was in the same position as another"
        );
    }

    #[test]
    fn tree_deletion() {
        let mut tree = SumTree::new();

        tree.insert(5, 42);
        tree.insert(6, 42);
        tree.insert(5, 42);

        tree.remove(5);
        tree.remove(4);

        assert_eq!(
            tree.len(),
            1,
            "There should be one element left in the tree"
        );

        assert_eq!(*tree.root(), 42);

        tree.remove(6);
        assert!(tree.is_empty(), "The tree should be empty");
        assert_eq!(
            *tree.root(),
            u8::EMPTY_SUBTREE,
            "Since the tree is empty the root should be the first empty item"
        );
    }

    #[test]
    #[should_panic(
        expected = "index out of bounds: the capacity is 8 but the index is 8"
    )]
    fn tree_insertion_out_of_bounds() {
        let mut tree = SumTree::new();
        tree.insert(tree.capacity(), 42);
    }



    type RangeTree = Tree<Option<Range>, H, A>;


    #[derive(Debug, Clone, Copy, PartialEq)]
    struct Range {
        min: u64,
        max: u64,
    }

    impl Range {
        pub fn new(min: u64, max: u64) -> Self {
            Range { min, max }
        }
    }

    impl Aggregate<A> for Option<Range> {
        const EMPTY_SUBTREE: Self = None;

        fn aggregate(items: [&Self; A]) -> Self {
            let mut block_height_range = None;

            for item in items {
                block_height_range = match (block_height_range, item.as_ref()) {
                    (None, None) => None,
                    (None, Some(r)) => Some(*r),
                    (Some(r), None) => Some(r),
                    (Some(existing_range), Some(item_range)) => {
                        let min =
                            core::cmp::min(item_range.min, existing_range.min);
                        let max =
                            core::cmp::max(item_range.max, existing_range.max);
                        Some(Range { min, max })
                    }
                };
            }

            block_height_range
        }
    }

    #[test]
    fn smallest_subtree() {
        let empty_root: Option<Range> = None;

        let mut tree = RangeTree::new();
        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, empty_root);
        assert_eq!(height, 0);
        drop(smallest_subtree);

        tree.insert(0, Some(Range::new(0, 0)));

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, Some(Range::new(0, 0)));
        assert_eq!(height, 1);
        drop(smallest_subtree);

        tree.insert(1, Some(Range::new(1, 1)));

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, Some(Range::new(0, 1)));
        assert_eq!(height, 1);
        drop(smallest_subtree);

        tree.insert(2, Some(Range::new(2, 2)));

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, Some(Range::new(0, 2)));
        assert_eq!(height, 2);
        drop(smallest_subtree);

        tree.insert(3, Some(Range::new(3, 3)));

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, Some(Range::new(0, 3)));
        assert_eq!(height, 2);
        drop(smallest_subtree);

        tree.insert(7, Some(Range::new(7, 7)));

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, Some(Range::new(0, 7)));
        assert_eq!(height, 3);
        drop(smallest_subtree);

        tree.remove(0);
        tree.remove(1);
        tree.remove(2);

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, Some(Range::new(3, 7)));
        assert_eq!(height, 3);
        drop(smallest_subtree);

        tree.remove(3);
        tree.insert(4, Some(Range::new(4, 4)));

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, Some(Range::new(4, 7)));
        assert_eq!(height, 2);
        drop(smallest_subtree);

        tree.remove(4);

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert_eq!(*smallest_subtree, Some(Range::new(7, 7)));
        assert_eq!(height, 1);
        drop(smallest_subtree);

        tree.remove(7);

        let (smallest_subtree, height) = tree.smallest_subtree();
        assert!(smallest_subtree.is_none());
        assert_eq!(height, 0);
    }

    #[cfg(feature = "rkyv-impl")]
    mod rkyv_impl {
        use super::SumTree;

        #[test]
        fn serde() {
            let mut tree = SumTree::new();

            tree.insert(5, 42);
            tree.insert(6, 42);
            tree.insert(5, 42);

            let tree_bytes = rkyv::to_bytes::<_, 128>(&tree)
                .expect("Archiving a tree should succeed")
                .to_vec();

            let archived_tree = rkyv::from_bytes::<SumTree>(&tree_bytes)
                .expect("Deserializing a tree should succeed");

            assert_eq!(tree, archived_tree);
        }
    }
}
