#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

#define INFO "ptree: "

struct TreeNode {
  int val;
  struct TreeNode *first_child;
  struct TreeNode *next_sibling;
};

struct LinkedListNode {
  struct TreeNode *data;
  struct LinkedListNode *next;
};

static struct TreeNode *create_node(int val) {
  struct TreeNode *node = kmalloc(sizeof(struct TreeNode), GFP_KERNEL);
  node->val = val;
  node->first_child = NULL;
  node->next_sibling = NULL;
  return node;
}

static void add_child(struct TreeNode *parent, struct TreeNode *child) {
  child->next_sibling = parent->first_child;
  parent->first_child = child;
}

static struct TreeNode *rebuild_tree(void) {
  struct task_struct *task;

  int max_pid = 0;
  for_each_process(task) {
    pid_t pid = task->pid;
    if (max_pid < pid) {
      max_pid = pid;
    }
  }
  printk("num_pairs = %d\n", max_pid + 1);

  // 创建哈希表来存储节点的值和节点的映射关系
  struct LinkedListNode **hash_table = (struct LinkedListNode **)kcalloc(
      max_pid + 1, sizeof(struct LinkedListNode *), GFP_KERNEL);

  // 创建根节点
  struct TreeNode *root;
  for_each_process(task) {
    pid_t pid = task->pid;
    pid_t ppid = task->real_parent->pid;

    int parent_val = ppid;
    int child_val = pid;

    // 如果父节点尚未插入哈希表，则创建新节点并插入哈希表
    struct TreeNode *parent;
    if (hash_table[parent_val] == NULL) {
      parent = create_node(parent_val);
      if (parent_val == 0) {
        root = parent;
      }
      struct LinkedListNode *list_node =
          kmalloc(sizeof(struct LinkedListNode), GFP_KERNEL);
      list_node->data = parent;
      list_node->next = hash_table[parent_val];
      hash_table[parent_val] = list_node;
    } else {
      // 否则，在哈希表中查找父节点
      struct LinkedListNode *list_node = hash_table[parent_val];
      while (list_node != NULL && list_node->data->val != parent_val) {
        list_node = list_node->next;
      }
      parent = list_node->data;
    }

    // 如果子节点尚未插入哈希表，则创建新节点并插入哈希表
    struct TreeNode *child;
    if (hash_table[child_val] == NULL) {
      child = create_node(child_val);
      struct LinkedListNode *list_node =
          kmalloc(sizeof(struct LinkedListNode), GFP_KERNEL);
      list_node->data = child;
      list_node->next = hash_table[child_val];
      hash_table[child_val] = list_node;
    } else {
      // 否则，在哈希表中查找子节点
      struct LinkedListNode *list_node = hash_table[child_val];
      while (list_node != NULL && list_node->data->val != child_val) {
        list_node = list_node->next;
      }
      child = list_node->data;
    }

    // 将子节点插入到父节点的子节点列表中
    add_child(parent, child);
  }

  // 返回根节点
  return root;
}

// 释放进程树
static void free_tree(struct TreeNode *root) {
  struct TreeNode *child = root->first_child;
  while (child != NULL) {
    struct TreeNode *next_child = child->next_sibling;
    free_tree(child);
    child = next_child;
  }
  kfree(root);
}

// 打印进程树
void print_tree(struct TreeNode *root, int level, bool is_last) {
  // 打印连接线
  for (int i = 0; i < level; i++) {
    printk(i ? "|"
             : " "
               "   ");
  }
  printk(is_last ? "└── " : "├── ");
  printk("%d\n", root->val);

  // 递归遍历子节点
  struct TreeNode *child = root->first_child;
  while (child != NULL) {
    // 如果是最后一个子节点，则打印不同的连接线
    if (child->next_sibling == NULL) {
      print_tree(child, level + 1, true);
    } else {
      print_tree(child, level + 1, false);
    }
    child = child->next_sibling;
  }
}

static int __init ptree_init(void) {
  struct TreeNode *root = rebuild_tree();
  print_tree(root, 0, false);
  free_tree(root);
  return 0;
}

static void __exit ptree_exit(void) {}

MODULE_LICENSE("GPL");

module_init(ptree_init);
module_exit(ptree_exit);