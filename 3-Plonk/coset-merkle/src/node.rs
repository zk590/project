
use alloc::boxed::Box;
use core::cell::{Ref, RefCell};

use crate::{init_fixed_array, level_capacity, Aggregate};

#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct Node<T, const H: usize, const A: usize> {
    item: RefCell<Option<T>>,
    pub(crate) children: [Option<Box<Node<T, H, A>>>; A],
}

impl<T, const H: usize, const A: usize> Node<T, H, A>
where
    T: Aggregate<A>,
{
    const INIT_NODE: Option<Box<Node<T, H, A>>> = None;

    /// 创建一个空节点。
    pub(crate) const fn new() -> Self {
        debug_assert!(H > 0, "Height must be larger than zero");
        debug_assert!(A > 0, "Arity must be larger than zero");

        Self {
            item: RefCell::new(None),
            children: [Self::INIT_NODE; A],
        }
    }
    /// 读取当前节点聚合值；若缓存为空则按子节点现算并缓存。
    pub(crate) fn aggregated_item(&self) -> Ref<'_, T> {

        if self.item.borrow().is_none() {

            let empty_subtree = &T::EMPTY_SUBTREE;
            let mut item_refs = [empty_subtree; A];

            let child_items: [Option<Ref<'_, T>>; A] =
                init_fixed_array(|child_index| {
                    self.children[child_index]
                        .as_ref()
                        .map(|child_node| child_node.aggregated_item())
                });

            let mut has_children = false;
            item_refs
                .iter_mut()
                .zip(&child_items)
                .for_each(|(item_ref_slot, child_item)| {
                    if let Some(child_item) = child_item {
                        *item_ref_slot = child_item;
                        has_children = true;
                    }
                });

            if has_children {
                self.item.replace(Some(T::aggregate(item_refs)));
            } else {
                self.item.replace(Some(T::EMPTY_SUBTREE));
            }
        }


        Ref::map(self.item.borrow(), |item| item.as_ref().unwrap())
    }
    /// 计算给定高度与全局位置对应的子节点索引与子位置。
    pub(crate) fn child_index_and_offset(
        height: usize,
        position: u64,
    ) -> (usize, u64) {
        let child_cap = level_capacity(A as u64, H - height - 1);



        #[allow(clippy::cast_possible_truncation)]
        let child_index = (position / child_cap) as usize;
        let child_pos = position % child_cap;

        (child_index, child_pos)
    }
    /// 递归插入叶子，并使沿途节点聚合缓存失效。
    pub(crate) fn insert(
        &mut self,
        height: usize,
        position: u64,
        item: impl Into<T>,
    ) {
        if height == H {
            self.item.replace(Some(item.into()));
            return;
        }
        self.item.replace(None);

        let (child_index, child_pos) =
            Self::child_index_and_offset(height, position);

        let selected_child = &mut self.children[child_index];
        if selected_child.is_none() {
            *selected_child = Some(Box::new(Node::new()));
        }


        let selected_child = self.children[child_index].as_mut().unwrap();
        Self::insert(selected_child, height + 1, child_pos, item);
    }

    /// 递归删除叶子，并返回 `(被删元素, 当前节点是否仍有子节点)`。
    pub(crate) fn remove(&mut self, height: usize, position: u64) -> (T, bool) {
        if height == H {

            let item = self.item.take().unwrap();
            return (item, false);
        }
        self.item.replace(None);

        let (child_index, child_pos) =
            Self::child_index_and_offset(height, position);

        let selected_child = self.children[child_index]
            .as_mut()
            .expect("There should be a child at this position");
        let (removed_item, child_has_children) =
            Self::remove(selected_child, height + 1, child_pos);

        if !child_has_children {
            self.children[child_index] = None;
        }

        let mut has_children = false;
        for child_node in &self.children {
            if child_node.is_some() {
                has_children = true;
                break;
            }
        }

        (removed_item, has_children)
    }
}

#[cfg(feature = "rkyv-impl")]
mod rkyv_impl {
    use super::Node;

    use alloc::boxed::Box;
    use core::cell::RefCell;

    use bytecheck::CheckBytes;
    use rkyv::{
        out_field, ser::Serializer, Archive, Archived, Deserialize, Fallible,
        Resolver, Serialize,
    };

    #[derive(CheckBytes)]
    #[check_bytes(
        bound = "__C: rkyv::validation::ArchiveContext, <__C as rkyv::Fallible>::Error: bytecheck::Error"
    )]
    pub struct ArchivedNode<T: Archive, const H: usize, const A: usize> {
        item: Archived<Option<T>>,
        #[omit_bounds]
        children: Archived<[Option<Box<Node<T, H, A>>>; A]>,
    }

    pub struct NodeResolver<T: Archive, const H: usize, const A: usize> {
        item: Resolver<Option<T>>,
        children: Resolver<[Option<Box<Node<T, H, A>>>; A]>,
    }

    impl<T, const H: usize, const A: usize> Archive for Node<T, H, A>
    where
        T: Archive,
    {
        type Archived = ArchivedNode<T, H, A>;
        type Resolver = NodeResolver<T, H, A>;

        unsafe fn resolve(
            &self,
            pos: usize,
            resolver: Self::Resolver,
            out: *mut Self::Archived,
        ) {
            let (item_pos, item) = out_field!(out.item);
            let (children_pos, children) = out_field!(out.children);

            self.item
                .borrow()
                .resolve(pos + item_pos, resolver.item, item);
            self.children.resolve(
                pos + children_pos,
                resolver.children,
                children,
            );
        }
    }

    impl<S, T, const H: usize, const A: usize> Serialize<S> for Node<T, H, A>
    where
        S: Serializer + ?Sized,
        T: Archive + Serialize<S>,
    {
        fn serialize(
            &self,
            serializer: &mut S,
        ) -> Result<Self::Resolver, S::Error> {
            let item = self.item.borrow();

            let item = item.serialize(serializer)?;
            let children = self.children.serialize(serializer)?;

            Ok(Self::Resolver { item, children })
        }
    }

    impl<D, T, const H: usize, const A: usize> Deserialize<Node<T, H, A>, D>
        for ArchivedNode<T, H, A>
    where
        D: Fallible + ?Sized,
        T: Archive,
        Archived<T>: Deserialize<T, D>,
    {
        fn deserialize(
            &self,
            deserializer: &mut D,
        ) -> Result<Node<T, H, A>, D::Error> {
            let item = self.item.deserialize(deserializer)?;
            let children = self.children.deserialize(deserializer)?;
            Ok(Node {
                item: RefCell::new(item),
                children,
            })
        }
    }
}
