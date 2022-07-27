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

// Merkle Tree �ṹ�嶨�� 
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

// ��ӡ Merkle tree 
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

// ����hashֵ RSA����ǩ��sha256
uint hash_string(const char* key) {
	uint8_t* m=_mbedtls_rsa_sign_test(key);
	return m;
}




MTNode* Find_Last_Node(MTNode* mt) {
	MTNode* p = mt, * tmp;

	if (p->left == NULL && p->right == NULL)	// Ҷ�ӽڵ� 
		return p;
	else if (p->right == NULL && p->left != NULL)
		return Find_Last_Node(p->left);
	else if (p->right != NULL)
		return Find_Last_Node(p->right);
}

// �������һ���ڵ㣬�ҵ������λ�� 
MTNode* Find_Empty_Node(MTNode* mt) {
	MTNode* p = mt->parent;

	while (p->left != NULL && p->right != NULL && p->parent != NULL) {
		p = p->parent;
	}
	if (p->parent == NULL && p->left != NULL && p->right != NULL) {		
		return NULL;
	}
	else {
		//printf("��ǰ�ڵ�λ�ã�p->hash_num=%d \n", p->hash_num); 
		return p;
	}
}

// �������Ĺ�ϣֵ 
void hash_Merkle(MTNode* mt)
{
	mt->hash_num = hash_string(mt->data);
}

// Merkle tree ��ʼ�� (�ݹ�ʵ��)
MTNode* Creat_MTree(MTNode* mt, char* arr, int nums, int tree_depth)
{
	MTNode* node, * tmp, * p;
	int i;
	if (nums == 0) {
		// nums ����0ʱ�����������ȣ���ʱ����merkle treeͷ���
		// ���½ڵ�Ĺ�ϣֵ  
		//hash_Merkle(mt, tree_depth);
		printf("�������\n");

		if (mt != NULL) {
			first = 0;
			printf("\n��ʼ��ӡ��ǰ Merkle ��:\n");
			Print_MTree(mt, mt->hash_num);
			printf("\n");
		}
		return mt;
	}
	else {
		// ÿ�����һ��Ҷ�ӽڵ㣬�����������������
		// ����һ������� 
		New_Merkle_Node(node, 0);
		node->data = arr;
		hash_Merkle(node);

		// ��� mt Ϊ�գ�˵����ǰû����	
		if (mt == NULL) {
			// ����ͷ���
			New_Merkle_Node(mt, 1);
			mt->left = node; 	// ��ͷ�ڵ㸳ֵ 
			node->parent = mt;
			hash_Merkle(node);
			// ��ǰ���߶� +1 
			tree_depth++;

			// �ݹ�
			mt = Creat_MTree(mt, arr + 1, nums - 1, tree_depth);
		}
		// ��� mt ��Ϊ��,mtΪͷ��� 
		else
		{
			p = Find_Empty_Node(Find_Last_Node(mt));	

			// ���flag Ϊ1 ˵�����ڿյ� ��Ҷ�ӽڵ� 
			if (p != NULL) {
				// �������¾���Ҷ�ӽڵ㣬��ֱ�Ӹ�ֵ 
				if (p->left->hash_num == 0 && p->right == NULL)
				{
					p->right = node;
					node->parent = p;
					hash_Merkle(node);
				}
				else
				{
					i = p->hash_num - 1;
					// ����һ���µ�ͷ���
					New_Merkle_Node(tmp, i);
					p->right = tmp;
					tmp->parent = p;
					p = p->right;

					i--;
					// ����������ȴ���ͬ����ȵ����� 
					while (i > 0) {
						// �������
						New_Merkle_Node(tmp, i);
						p->left = tmp;
						tmp->parent = p;
					
						p = p->left;
						i--;
					}

					// Ҷ�ӽڵ㸳ֵ 
					p->left = node;
					node->parent = p;
					hash_Merkle(node);
				}
				mt = Creat_MTree(mt, arr + 1, nums - 1, tree_depth);
			}
			//���û�пյ�Ҷ�ӽڵ㣬���½�һ��ͷ��� 
			else
			{
				tmp = mt;	// ���浱ǰͷ���
				tree_depth++; 		// ���߶� +1 

				// ����һ���µ�ͷ���
				New_Merkle_Node(mt, tree_depth);
				mt->left = tmp; 	// ��ͷ�ڵ㸳ֵ 
				tmp->parent = mt;

				// ����ͷ��� -  Ҷ�ӽڵ� ֮������нڵ� 
				i = tree_depth - 1;	// �ڶ���ڵ� 

				// ͷ��� right ��ֵ  
				New_Merkle_Node(tmp, i);
				mt->right = tmp;
				tmp->parent = mt;

				i--;
				p = mt->right;

				// ����������ȴ���ͬ����ȵ����� 
				while (i > 0) {
					// �������
					New_Merkle_Node(tmp, i);
					p->left = tmp;
					tmp->parent = p;

					p = p->left;
					i--;
				}
				// Ҷ�ӽڵ㸳ֵ 
				p->left = node;
				node->parent = p;
				hash_Merkle(node);
				// �ݹ���� 
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

