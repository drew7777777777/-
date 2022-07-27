#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

//#if defined(MBEDTLS_RSA_C)

#include <stdio.h>
#include "string.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include <stdio.h>


static char buf[516];
typedef unsigned int uint;

// Merkle Tree 结构体定义 
typedef struct MerkleTreeNode {
    struct MerkleTreeNode* left;
    struct MerkleTreeNode* right;
    struct MerkleTreeNode* parent;
    uint8_t* hash_num;		 
    char* data;
}MTNode;


#define New_Merkle_Node(mt, tree_depth) {	\
	mt = (MTNode *)malloc(sizeof(MTNode)); \
	mt->left = NULL; \
	mt->right = NULL; \
	mt->parent = NULL; \
	mt->hash_num = NULL; \
	mt->data = NULL;	\
	}

static void _dump_buf(uint8_t* buf, uint32_t len)
{
    int i;

    for (i = 0; i < len; i++) {
        printf("%s%02X%s", i % 16 == 0 ? "\r\n\t" : " ",
            buf[i],
            i == len - 1 ? "\r\n" : "");
    }
}

static uint8_t output_buf[2048 / 8];

uint8_t* _mbedtls_rsa_sign_test(const char* m)
{
    int ret;
    const char* msg = m;

    const char* pers = "rsa_sign_test";
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context ctx;

    /* 1. init structure */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);

    /* 2. update seed with we own interface ported */
    printf("\n  . Seeding the random number generator...");

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers,
        strlen(pers));
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf(" ok\n");

    /* 3. generate an RSA keypair */
    printf("\n  . Generate RSA keypair...");

    ret = mbedtls_rsa_gen_key(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_rsa_gen_key returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf(" ok\n");

    /* 4. sign */
    printf("\n  . RSA pkcs1 sign...");

    ret = mbedtls_rsa_pkcs1_sign(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, strlen(msg), (uint8_t*)msg, output_buf);
    if (ret != 0) {
        printf(" failed\n  ! mbedtls_rsa_pkcs1_sign returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf(" ok\n");

    /* show sign result */
    _dump_buf(output_buf, sizeof(output_buf));

    /* 5. verify sign*/
    printf("\n  . RSA pkcs1 verify...");

    ret = mbedtls_rsa_pkcs1_verify(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, strlen(msg), (uint8_t*)msg, output_buf);

    if (ret != 0) {
        printf(" failed\n  ! mbedtls_rsa_pkcs1_encrypt returned %d(-0x%04x)\n", ret, -ret);
        goto exit;
    }
    printf(" ok\n");

exit:

    /* 5. release structure */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_rsa_free(&ctx);

    return output_buf;
}

// 打印 Merkle tree 
int first = 0;
void Print_Merkle_Tree(MTNode* mt, int high)
{
	MTNode* p = mt;
	int i;

	if (p == NULL) {
		return;
	}
	if (p->left == NULL && p->right == NULL) {
		printf("\n");

		printf("--->%2d\n", *(p->data));
		first = 1;

		return;
	}
	else {
		Print_Merkle_Tree(mt->left, high);

		if (first == 1) {
			printf("--->");
		}
		else
			printf("--->");

		printf("%2d", p->hash_num);
		first = 0;

		Print_Merkle_Tree(mt->right, high);
		//printf("\n");
	}
}

// 计算hash值 RSA数字签名sha256
uint hash_string(const char* key) {
	uint8_t* m=_mbedtls_rsa_sign_test(key);
	return m;
}




MTNode* Find_Last_Node(MTNode* mt) {
	MTNode* p = mt, * tmp;

	if (p->left == NULL && p->right == NULL)	// 叶子节点 
		return p;
	else if (p->right == NULL && p->left != NULL)
		return Find_Last_Node(p->left);
	else if (p->right != NULL)
		return Find_Last_Node(p->right);
}

// 根据最后一个节点，找到插入的位置 
MTNode* Find_Empty_Node(MTNode* mt) {
	MTNode* p = mt->parent;

	while (p->left != NULL && p->right != NULL && p->parent != NULL) {
		p = p->parent;
	}
	if (p->parent == NULL && p->left != NULL && p->right != NULL) {		
		return NULL;
	}
	else {
		//printf("当前节点位置，p->hash_num=%d \n", p->hash_num); 
		return p;
	}
}

// 更新树的哈希值 
void hash_Merkle(MTNode* mt)
{
	mt->hash_num = hash_string(mt->data);
}

// Merkle tree 初始化 (递归实现)
MTNode* Creat_MTree(MTNode* mt, char* arr, int nums, int tree_depth)
{
	MTNode* node, * tmp, * p;
	int i;
	if (nums == 0) {
		// nums 等于0时，数据添加完比，此时返回merkle tree头结点
		// 更新节点的哈希值  
		//hash_Merkle(mt, tree_depth);
		printf("创建完毕\n");

		if (mt != NULL) {
			first = 0;
			printf("\n开始打印当前 Merkle 树:\n");
			Print_MTree(mt, mt->hash_num);
			printf("\n");
		}
		return mt;
	}
	else {
		// 每次添加一个叶子节点，优先左树，其次右树
		// 创建一个树结点 
		New_Merkle_Node(node, 0);
		node->data = arr;
		hash_Merkle(node);

		// 如果 mt 为空，说明当前没有树	
		if (mt == NULL) {
			// 创建头结点
			New_Merkle_Node(mt, 1);
			mt->left = node; 	// 结头节点赋值 
			node->parent = mt;
			hash_Merkle(node);
			// 当前树高度 +1 
			tree_depth++;

			// 递归
			mt = Creat_MTree(mt, arr + 1, nums - 1, tree_depth);
		}
		// 如果 mt 不为空,mt为头结点 
		else
		{
			p = Find_Empty_Node(Find_Last_Node(mt));	

			// 如果flag 为1 说明存在空的 右叶子节点 
			if (p != NULL) {
				// 如果最底下就是叶子节点，就直接赋值 
				if (p->left->hash_num == 0 && p->right == NULL)
				{
					p->right = node;
					node->parent = p;
					hash_Merkle(node);
				}
				else
				{
					i = p->hash_num - 1;
					// 创建一个新的头结点
					New_Merkle_Node(tmp, i);
					p->right = tmp;
					tmp->parent = p;
					p = p->right;

					i--;
					// 根据树的深度创建同样深度的左树 
					while (i > 0) {
						// 创建结点
						New_Merkle_Node(tmp, i);
						p->left = tmp;
						tmp->parent = p;
					
						p = p->left;
						i--;
					}

					// 叶子节点赋值 
					p->left = node;
					node->parent = p;
					hash_Merkle(node);
				}
				mt = Creat_MTree(mt, arr + 1, nums - 1, tree_depth);
			}
			//如果没有空的叶子节点，则新建一个头结点 
			else
			{
				tmp = mt;	// 保存当前头结点
				tree_depth++; 		// 树高度 +1 

				// 创建一个新的头结点
				New_Merkle_Node(mt, tree_depth);
				mt->left = tmp; 	// 结头节点赋值 
				tmp->parent = mt;

				// 创建头结点 -  叶子节点 之间的所有节点 
				i = tree_depth - 1;	// 第二层节点 

				// 头结点 right 赋值  
				New_Merkle_Node(tmp, i);
				mt->right = tmp;
				tmp->parent = mt;

				i--;
				p = mt->right;

				// 根据树的深度创建同样深度的左树 
				while (i > 0) {
					// 创建结点
					New_Merkle_Node(tmp, i);
					p->left = tmp;
					tmp->parent = p;

					p = p->left;
					i--;
				}
				// 叶子节点赋值 
				p->left = node;
				node->parent = p;
				hash_Merkle(node);
				// 递归调用 
				mt = Creat_MTree(mt, arr + 1, nums - 1, tree_depth);
			}
		}
	}
}

int main()
{
	// , This Is Cielle.
	char* array[] = { "11", "22", "33" ,"44"  };
	MTNode* mt = NULL;
	_mbedtls_rsa_sign_test("11");
	Creat_MTree(mt, array, 4, 0);


	return 0;
}

