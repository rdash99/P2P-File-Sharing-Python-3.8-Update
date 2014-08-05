#include <iostream>
#include <gmp.h>
using namespace std;
class RSA_Encrypt{

	mpz_t p,q,n,e,fin,d;
	public:
	RSA_Encrypt(int key_size){
		mpz_init(p);
		mpz_init(q);
		mpz_init(n);
		mpz_init(e);
		mpz_init(fin);
		mpz_init(d);
		gmp_randstate_t st;
  		gmp_randinit_default(st);
	//	printf("here\n");
		
  		mpz_urandomb(p,st,512);
 	 	mpz_urandomb(q,st,512);
		//gmp_printf("p=%Zd\n q=%Zd",p,q);
 	 	mpz_nextprime(p,p);
  		mpz_nextprime(q,q);
	//	gmp_printf("p=%Zd   q=%Zd    ",p,q);
  		mpz_mul(n, p, q);
  		mpz_sub_ui(p, p, 1UL);
  		mpz_sub_ui(q, q, 1UL);
  		mpz_mul(fin, p, q);
		//mpz_mul(fin, p, q);
   
	   	mpz_t num,gcd;
		mpz_init(num);
		mpz_init(gcd);

		mpz_urandomb(e,st,300);//choose 'e' to be atleast 300-bits initially...
		
		//mpz_set_ui(e,3);
		mpz_set_ui(num,1);
		while(1)
		{
			mpz_gcd(gcd,e,fin);
			if(mpz_cmp(gcd,num)==0)
				break;
			else 
				mpz_add_ui(e,e,1);
		}
			
	    mpz_invert(d, e, fin);
	}
   
		string get_public_key(){
			return mpz_get_str(NULL,10,e);
		}
		/*No need of this method, since it is a private key... */
/*		mpz_t& get_private_key(){
			return d;
		}*/
		string get_n(){
			return mpz_get_str(NULL,10,n);
		}
		void encrypt(mpz_t &m,mpz_t &c){
			mpz_powm(m,c,e,n);
		//	return c;
		}
		void decrypt(mpz_t &m,mpz_t &c){
			mpz_powm(m,c,d,n);
		//	return c;
		}
		string get_decoded_string(mpz_t& val)
		{
			string ans="",rev_ans="";
			mpz_t rem;
			unsigned int tmp;
			mpz_init(rem);
			while(mpz_cmp_si(val,0))
			{
				mpz_mod_ui(rem,val,256);
				tmp = mpz_get_ui(rem);
				rev_ans += tmp;
				mpz_div_ui(val, val,256);
			}
			int len = rev_ans.length();
			for(int i=len-1;i>=0;--i)
				ans += rev_ans[i];
			return ans;
		}
		/*
		Encrypt takes argument as the string... 
		converts it to a number...
		does the exponentiation and returns the number as string...
		*/
		void get_encoded_number(string msg, mpz_t& ans)
		{
			mpz_set_ui(ans,0);
			int len = msg.length();
			for(int i=0; i<len;++i)
			{
				mpz_mul_ui(ans, ans, 256);
				mpz_add_ui(ans, ans, msg[i]);
			}
	//		cout<<mpz_get_str(NULL, 10, ans)<<"***"<<endl;
		}

		string encrypt(string msg)
		{
			mpz_t val;
			mpz_init(val);
			get_encoded_number(msg,val);
			mpz_t res;
			mpz_init(res);
			encrypt(res,val);
			return mpz_get_str(NULL, 10,res);
		}

		string decrypt(string cip_txt)
		{
			mpz_t val,cip;
			mpz_init(val);
			mpz_init(cip);
			mpz_set_str(cip, cip_txt.c_str(), 10);
			decrypt(val, cip);
			return get_decoded_string(val);
		}
	};
///*
	int main(){
		
		mpz_t z;
		mpz_init(z);
		mpz_set_str(z,"1000000000000",10);
		mpz_nextprime(z,z);
		gmp_printf("p=%Zd\n",z);		
		RSA_Encrypt b;
		string ip;
		cin>>ip;
		string zz=b.encrypt(ip);
		cout<<zz<<endl;
		cout<<b.decrypt(zz)<<endl;
	}
//*/
