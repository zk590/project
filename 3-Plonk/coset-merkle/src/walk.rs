
use core::cell::Ref;

use crate::{Aggregate, Node, Tree};


#[derive(Debug, Clone)]
pub struct Walk<'a, T, W, const H: usize, const A: usize> {
    root: &'a Node<T, H, A>,
    walker: W,


    path: [Option<&'a Node<T, H, A>>; H],
    indices: [usize; H],
}

impl<'a, T, W, const H: usize, const A: usize> Walk<'a, T, W, H, A>
where
    T: Aggregate<A>,
    W: Fn(&T) -> bool,
{
    /// 创建树遍历器，按 `walker` 过滤节点。
    pub(crate) fn new(tree: &'a Tree<T, H, A>, walker: W) -> Self {
        Self {
            root: &tree.root,
            walker,
            path: [None; H],
            indices: [0; H],
        }
    }


    /// 深度优先推进到下一个满足谓词的叶子项。
    pub(crate) fn advance_depth_first(
        &mut self,
        node: &'a Node<T, H, A>,
        level_index: usize,
    ) -> Option<Ref<'a, T>> {


        if level_index == H - 1 {
            let child_cursor = &mut self.indices[level_index];



            for child_index in *child_cursor..A {
                *child_cursor = child_index + 1;
                if let Some(leaf) = &node.children[child_index] {
                    let leaf = leaf.aggregated_item();
                    if (self.walker)(&*leaf) {
                        return Some(leaf);
                    }
                }
            }



            *child_cursor = 0;
            return None;
        }




        if self.path[level_index].is_none() {
            for child_index in 0..A {
                self.indices[level_index] = child_index;
                if let Some(child) = &node.children[child_index] {
                    let child = child.as_ref();
                    if (self.walker)(&*child.aggregated_item()) {
                        self.path[level_index] = Some(child);
                        break;
                    }
                }
            }
        }



        //


        if let Some(child) = self.path[level_index] {
            if let Some(item) =
                self.advance_depth_first(child, level_index + 1)
            {
                return Some(item);
            }

            for child_index in self.indices[level_index] + 1..A {
                self.indices[level_index] = child_index;

                if let Some(child) = &node.children[child_index] {
                    let child = child.as_ref();
                    if (self.walker)(&*child.aggregated_item()) {
                        self.path[level_index] = Some(child);
                        match self
                            .advance_depth_first(child, level_index + 1)
                        {
                            Some(item) => return Some(item),
                            None => continue,
                        }
                    }
                }
            }

            self.path[level_index] = None;
            self.indices[level_index] = 0;
        }

        None
    }
}

impl<'a, T, W, const H: usize, const A: usize> Iterator for Walk<'a, T, W, H, A>
where
    T: Aggregate<A>,
    W: Fn(&T) -> bool,
{
    type Item = Ref<'a, T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.advance_depth_first(self.root, 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Aggregate, Tree};

    #[derive(Debug, Default, Clone, Copy)]
    struct Max(u64);

    impl From<u64> for Max {
        fn from(i: u64) -> Self {
            Max(i)
        }
    }

    const HEIGHT_2: usize = 2;
    const HEIGHT_17: usize = 17;

    const ARITY_2: usize = 2;
    const ARITY_4: usize = 4;

    const LARGER_THAN: u64 = 6;

    impl<const A: usize> Aggregate<A> for Max {
        const EMPTY_SUBTREE: Self = Max(0);

        fn aggregate(items: [&Self; A]) -> Self {
            Self(items.into_iter().map(|i| i.0).max().unwrap_or_default())
        }
    }

    type SmallTree = Tree<Max, HEIGHT_2, ARITY_2>;
    type LargeTree = Tree<Max, HEIGHT_17, ARITY_4>;

    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn is_larger_than(max: &Max) -> bool {
        max.0 > LARGER_THAN
    }

    #[test]
    fn full_tree() {
        let mut tree = SmallTree::new();

        tree.insert(0, 2);
        tree.insert(1, 8);
        tree.insert(2, 16);
        tree.insert(3, 4);

        let mut walk = tree.walk(is_larger_than);

        assert!(matches!(walk.next(), Some(x) if x.0 == 8));
        assert!(matches!(walk.next(), Some(x) if x.0 == 16));
        assert!(matches!(walk.next(), None));
    }

    #[test]
    fn partial_tree() {
        let mut tree = SmallTree::new();

        tree.insert(1, 8);
        tree.insert(3, 4);

        let mut walk = tree.walk(is_larger_than);

        assert!(matches!(walk.next(), Some(x) if x.0 == 8));
        assert!(matches!(walk.next(), None));
    }

    #[test]
    fn large_tree() {
        let mut tree = LargeTree::new();

        tree.insert(0x42, 16);
        tree.insert(0x666, 1);
        tree.insert(0x1ead, 25);
        tree.insert(0xbeef, 8);
        tree.insert(0xca11, 25);
        tree.insert(0xdead, 4);

        let mut walk = tree.walk(is_larger_than);

        assert!(matches!(walk.next(), Some(x) if x.0 == 16));
        assert!(matches!(walk.next(), Some(x) if x.0 == 25));
        assert!(matches!(walk.next(), Some(x) if x.0 == 8));
        assert!(matches!(walk.next(), Some(x) if x.0 == 25));
        assert!(matches!(walk.next(), None));
    }

    #[test]
    fn empty_tree() {
        let tree = SmallTree::new();
        let mut walk = tree.walk(is_larger_than);
        assert!(matches!(walk.next(), None));
    }
}
