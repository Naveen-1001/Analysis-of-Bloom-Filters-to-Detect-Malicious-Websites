#include<bits/stdc++.h>
#include <chrono>
using namespace std;
using namespace std::chrono;
typedef long long int ll;
typedef long double ld;
ll layer2_m=10000000;
ll layer1_m=20000;
ll hash1(string str,ll m)
{   
    unsigned char ch;
    ll h(525201411107845655ull);
    for (ll i=0;i<str[i];i++) 
    {   
        ch=str[i];
        h = (h^ ch)%m;
        h = (h * 0x5bd1e9955bd1e995)%m;
        h = (h^ h >> 47)%m;
    }
    return h;
}

ll hash2(string str,ll m)
{   
    unsigned char ch;
    ll hash = 5381;
    for(int i=0;i<str.size();i++)
    {   
        ch=str[i];
        hash = (((hash << 5) + hash) + ch)%m;
    }
    return hash;
}

ll hash5(string str,ll m)
{   
    unsigned char ch;
    ll hash = 0;
    for(int i=0;i<str.size();i++)
    {   
        ch=str[i];
        hash = (ch + (hash << 6) + (hash << 16) - hash)%m;
    }
    return hash;
}

ll hash3(string str,ll m) 
{
	ll hashVal = 0;
    unsigned char ch;
	for(int i=0;i<str.size();i++)
    {   
        ch=str[i];
		hashVal = ((hashVal << 4) + ch)%m;
		ll g = (hashVal & 0xF0000000L)%m;
		if (g != 0) hashVal = (hashVal ^ g >> 24)%m;
		hashVal =(hashVal & ~g)%m;
	}
	return hashVal%m;
}

ll hash4(string str,ll m)
{
    ll h(3323198485ul);
    unsigned char ch;
    for (int i=0;i<str.length();i++) 
    {   
        ch=str[i];
        h =(h^ch)%m;
        h =(h* 0x5bd1e995)%m;
        h =(h^ h >> 15)%m;
    }
    return h;
}

int main(int argc, char *argv[])
{   
    vector<bitset<20000>>layer1(1);
    vector<bitset<10000000>>layer2(1);
    ifstream fin;
    fin.open(argv[1]);
    ll count_good=0;
    ll count_bad=0;
    string line;
    string temp;
    ll count=0;
    while(getline(fin,line))
    {   
        count++;
        vector<string>row;
        stringstream s(line);
        string word;
        while(getline(s ,word, ','))
        {
            row.push_back(word);
        }
        if(row.size()!=2) continue;
        if(row[1]=="bad")
        {   
            count_bad++;
            layer1[0].set(hash2(row[0],layer1_m));
            /*
            layer1[0].set(hash3(row[0],layer1_m));
            layer1[0].set(hash4(row[0],layer1_m));
            layer1[0].set(hash5(row[0],layer1_m));
            */
            layer2[0].set(hash2(row[0],layer2_m));
            layer2[0].set(hash3(row[0],layer2_m));
            
        }
        else
        {
            count_good++;
        }
        row.clear();
    }
    //Now bitset contains all the malicious urls
    //Generating validation dataset
    fin.clear();
    fin.seekg(0);

    vector<vector<string>>validation;
    ld validation_good=0;
    ld validation_bad=0;
    while(getline(fin,line))
    {
        vector<string>row;
        ll x=rand()%10;
        if(x>4) continue;
        
        string word;
        stringstream s(line);
        while(getline(s,word,','))
        {
            row.push_back(word);
        }
        if(row[1]=="bad") validation_bad++;
        else validation_good++;
        validation.push_back(row);
        row.clear();
    }
    
    ll true_positives=0;
    ld false_positives=0;
    ll false_negatives=0;
    ll true_negatives=0;
    
    ld falsePositivePercentage;
    auto start = high_resolution_clock::now();
    for(ll i=0;i<validation.size();i++)
    {   
        bool hasht2=layer1[0].test(hash2(validation[i][0],layer1_m));
        if(hasht2)
        {   
            bool layer2hasht2=layer2[0].test(hash2(validation[i][0],layer2_m));
            bool layer2hasht3=layer2[0].test(hash3(validation[i][0],layer2_m));
            
            if(layer2hasht2 and layer2hasht3)
            {
                if(validation[i][1]=="bad")
                {
                    true_positives++;
                }
                else
                {   
                    false_positives++;
                }       
            }
            else
            {   
                if(validation[i][1]=="bad")
                {
                    false_negatives++;
                }
                else 
                {
                    true_negatives++;
                }
            }
        }
        else 
        {   
            if(validation[i][1]=="bad")
            {
                false_negatives++;
            }
            else 
            {
                true_negatives++;
            }
        }
    }
    falsePositivePercentage=100*false_positives/(false_positives+true_negatives);
    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<microseconds>(stop - start);
    cout << "Average time taken to test membership of a URL:- "<< duration.count()/(validation_bad+validation_good) << " microseconds\n";
    cout<<"Total urls in dataset: "<<count_bad+count_good<<"\n";
    cout<<"Good urls in Validation set : "<<validation_good<<"\n";
    cout<<"Bad urls in Validation set : "<<validation_bad<<"\n";
    cout<<"True Positives : "<<true_positives<<"\n";
    cout<<"False Positives : "<<false_positives<<"\n";
    cout<<"True Negatives : "<<true_negatives<<"\n";
    cout<<"False Negatives : "<<false_negatives<<"\n";
    cout<<"% of False Positives : "<<falsePositivePercentage<<"\n";
    return 0;
}