#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>

struct TreeNode {
  int pid;    // 进程号
  char *comm; // 进程名
  struct TreeNode *first_child;
  struct TreeNode *next_sibling;
};

struct LinkedListNode {
  struct TreeNode *data;
  struct LinkedListNode *next;
};

static struct TreeNode *create_node(int pid, char *comm) {
  struct TreeNode *node = kmalloc(sizeof(struct TreeNode), GFP_KERNEL);
  node->pid = pid;
  node->first_child = NULL;
  node->next_sibling = NULL;
  node->comm = comm;
  return node;
}

static void add_child(struct TreeNode *parent, struct TreeNode *child) {
  child->next_sibling = parent->first_child;
  parent->first_child = child;
}

// 根据进程父子关系重建进程树
static struct TreeNode *rebuild_tree(void) {
  struct task_struct *task;
  int max_pid = 0;
  struct LinkedListNode **hash_table;
  // 创建根节点
  struct TreeNode *root;

  // 遍历进程描述符，找到进程id最大值
  for_each_process(task) {
    pid_t pid = task->pid;
    if (max_pid < pid) {
      max_pid = pid;
    }
  }

  // 创建哈希表来存储节点的值和节点的映射关系
  hash_table = (struct LinkedListNode **)kcalloc(
      max_pid + 1, sizeof(struct LinkedListNode *), GFP_KERNEL);

  for_each_process(task) {
    pid_t pid = task->pid;
    pid_t ppid = task->real_parent->pid;

    struct TreeNode *parent;
    struct TreeNode *child;
    struct LinkedListNode *list_node;

    // 如果父节点尚未插入哈希表，则创建新节点并插入哈希表
    if (hash_table[ppid] == NULL) {
      parent = create_node(ppid, task->real_parent->comm);
      if (ppid == 0) {
        root = parent;
      }
      list_node = kmalloc(sizeof(struct LinkedListNode), GFP_KERNEL);
      list_node->data = parent;
      list_node->next = hash_table[ppid];
      hash_table[ppid] = list_node;
    } else {
      // 否则，在哈希表中查找父节点
      list_node = hash_table[ppid];
      while (list_node != NULL && list_node->data->pid != ppid) {
        list_node = list_node->next;
      }
      parent = list_node->data;
    }

    // 如果子节点尚未插入哈希表，则创建新节点并插入哈希表
    if (hash_table[pid] == NULL) {
      child = create_node(pid, task->comm);
      list_node = kmalloc(sizeof(struct LinkedListNode), GFP_KERNEL);
      list_node->data = child;
      list_node->next = hash_table[pid];
      hash_table[pid] = list_node;
    } else {
      // 否则，在哈希表中查找子节点
      list_node = hash_table[pid];
      while (list_node != NULL && list_node->data->pid != pid) {
        list_node = list_node->next;
      }
      child = list_node->data;
    }

    // 将子节点插入到父节点的子节点列表中
    add_child(parent, child);
  }

  kfree(hash_table);

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
static void print_tree(struct TreeNode *root, char *prefix,
                       size_t prefix_length) {
  struct TreeNode *child;
  char *new_prefix;
  size_t new_prefix_length;

  // 递归遍历子节点
  child = root->first_child;
  while (child != NULL) {
    new_prefix_length = prefix_length + 4;
    new_prefix =
        (char *)kmalloc((new_prefix_length + 1) * sizeof(char), GFP_KERNEL);
    // 如果是最后一个子节点，则打印不同的连接线
    if (child->next_sibling == NULL) {
      printk("%s└── %d [%s]\n", prefix, child->pid, child->comm);
      sprintf(new_prefix, "%s    ", prefix);
    } else {
      printk("%s├── %d [%s]\n", prefix, child->pid, child->comm);
      sprintf(new_prefix, "%s|   ", prefix);
    }
    if (child->first_child)
      print_tree(child, new_prefix, new_prefix_length);
    kfree(new_prefix);
    child = child->next_sibling;
  }
}

static int __init ptree_init(void) {
  struct TreeNode *root;
  char *prefix;

  root = rebuild_tree();
  printk("%d [%s]", root->pid, root->comm);
  prefix = (char *)kmalloc(sizeof(char), GFP_KERNEL);
  prefix[0] = '\0';
  print_tree(root, prefix, 0);
  kfree(prefix);

  free_tree(root);
  return 0;
}

static void __exit ptree_exit(void) {}

MODULE_LICENSE("GPL");

module_init(ptree_init);
module_exit(ptree_exit);
