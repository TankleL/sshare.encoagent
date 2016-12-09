// secret-share.cpp
// Author: 廖添(Tankle L.)
// Date: October 1st, 2016


#include "precompile.h"
#include "datatypes.h"
#include "secret-share.h"

// //////////////////////////////////////////////////////////////////////////////////////////////
// DefaultRandomer
DefaultRandomer::DefaultRandomer()
{
	srand((unsigned int)time(nullptr));
}

int DefaultRandomer::Random() const
{
	return rand();
}

// //////////////////////////////////////////////////////////////////////////////////////////////
// FixedBuffer

FixedBuffer::FixedBuffer(const size_t& sizeInBytes) :
m_size(sizeInBytes), m_pData(new Enco::byte[sizeInBytes])
{}

FixedBuffer::~FixedBuffer()
{
	if (m_pData != nullptr)
	{
		delete[] m_pData;
	}
}

void FixedBuffer::Write(const size_t& offset, void const * const pSrc, const size_t& size)
{
	Enco::byte*	pStart = const_cast<Enco::byte*>(m_pData);
	pStart += offset;
	memcpy(pStart, pSrc, size);
}

void FixedBuffer::Read(void * const pDist, const size_t& offset, const size_t& size) const
{
	Enco::byte*	pStart = const_cast<Enco::byte*>(m_pData);
	pStart += offset;
	memcpy(pDist, pStart, size);
}

const size_t FixedBuffer::Size() const
{
	return m_size;
}

void* FixedBuffer::Buffer() const
{
	return m_pData;
}


// //////////////////////////////////////////////////////////////////////////////////////////////
// SecretSharer

void SecretSharer::ReleaseSharedSecrets(std::vector<FixedBuffer*>& sharedSecrets)
{
	std::vector<FixedBuffer*>::iterator iter;
	for (iter = sharedSecrets.begin();
		iter != sharedSecrets.end();
		++iter)
	{
		if (*iter != nullptr)
		{
			delete (*iter);
			*iter = nullptr;
		}
	}
}

// //////////////////////////////////////////////////////////////////////////////////////////////
// DefaultSecretSharer

const Enco::uint32 DefaultSecretSharer::m_cnst_shamir_threshold = ((Enco::uint32)65262);
const Enco::uint32 DefaultSecretSharer::m_cnst_shamir_prime = ((Enco::uint32)65809);

DefaultSecretSharer::DefaultSecretSharer(const Randomer& randomer) :
m_randomer(randomer)
{}

/*
* @implementation: Encode
* @description:
* @protocal:
*   ------------------------------------------
*   |  * shared index   [  4 bytes ]         |
*   |  * sha256 value   [ 32 bytes ]         |
*   |  * secret data    [  x bytes ]         |
*   ------------------------------------------
*/
bool DefaultSecretSharer::Encode(std::vector<FixedBuffer*>& sharedSecrets, const unsigned int& n, const unsigned int& k, const FixedBuffer& secretToShare)
{
	// release the possible trash data.
	ReleaseSharedSecrets(sharedSecrets);

	// fetch the size of origin secret to share.
	size_t originSize = secretToShare.Size();
	
	// calculate hash value
	unsigned char hash_value[32] = { 0 };
	sha256((const unsigned char*)secretToShare.Buffer(), (unsigned int)secretToShare.Size(), hash_value);
	
	// prepare the buffers to catch secrets
	for (Enco::uint32 i = 0; i < n; ++i)
	{
		FixedBuffer*	pBuf = new FixedBuffer(originSize * 4 + sizeof(Enco::uint32) + 32);
		Enco::uint32	sidx = i + 1;
		sharedSecrets.push_back(pBuf);
		pBuf->Write(0, &sidx, sizeof(Enco::uint32));		// record sequence
		pBuf->Write(sizeof(Enco::uint32), hash_value, 32);	// record hash
	}

	// loop each bytes
	Enco::byte const*	pChar = static_cast<Enco::byte const*>(secretToShare.Buffer());
	Enco::uint32*		pShrs = new Enco::uint32[n];
	const size_t		soff = sizeof(Enco::uint32) + 32;
	for (size_t idx = 0; idx < originSize; ++idx)
	{
		Enco::uint32 sec = *pChar;
		++pChar;

		_Encode(sec, n, k, m_randomer, pShrs);

		for (unsigned int i = 0; i < n; ++i)
		{
			sharedSecrets[i]->Write(sizeof(Enco::uint32)*idx + soff, &(pShrs[i]), sizeof(Enco::uint32));
		}
	}

	delete[] pShrs;

	if (sharedSecrets.size() > 0)
		return true;
	return false;
}

/*
* @implementation: Decode
* @description:
* @protocal:
*   ------------------------------------------
*   |  * shared index   [  4 bytes ]         |
*   |  * sha256 value   [ 32 bytes ]         |
*   |  * secret data    [  x bytes ]         |
*   ------------------------------------------
*/
bool DefaultSecretSharer::Decode(std::vector<FixedBuffer*>& recoverdSecrets, const std::vector<FixedBuffer*>& sharedSecrets)
{
	// release the possible trash data.
	ReleaseSharedSecrets(recoverdSecrets);

	if (sharedSecrets.size() <= 0)
		return false;

	// fetch indices and check the length of data.
	size_t			secLen;
	Enco::uint32*	pIndice = new Enco::uint32[sharedSecrets.size()];
	unsigned char	hash_value[32] = { 0 };
	unsigned char	tmp_hash_value[32] = { 0 };
	secLen = sharedSecrets[0]->Size();
	for (unsigned int i = 0; i < sharedSecrets.size(); ++i)
	{
		sharedSecrets[i]->Read(&(pIndice[i]), 0, sizeof(Enco::uint32));
		if (secLen != sharedSecrets[i]->Size())
		{
			if (pIndice != nullptr)
				delete[] pIndice;
			return false;
		}
		
		if (i == 0)
		{
			sharedSecrets[i]->Read(hash_value, sizeof(Enco::uint32), 32);
		}
		else
		{
			sharedSecrets[i]->Read(tmp_hash_value, sizeof(Enco::uint32), 32);
			if (memcmp(tmp_hash_value, hash_value, 32) != 0)
			{
				if (pIndice != nullptr)
					delete[] pIndice;
				return false;
			}
		}
	}
		
	Enco::uint32*	pShr = new Enco::uint32[sharedSecrets.size()];
	char			data;
	size_t			soff = sizeof(Enco::uint32) + 32;

	const size_t origin_secLen = (secLen - sizeof(Enco::uint32) - 32) / 4;
	FixedBuffer* pRecoverdSecret = new FixedBuffer(origin_secLen);
	for (size_t idx = 0; idx < origin_secLen; ++idx)
	{
		for (unsigned int j = 0; j < sharedSecrets.size(); ++j)
		{
			sharedSecrets[j]->Read(&pShr[j], sizeof(Enco::uint32)*idx + soff, sizeof(Enco::uint32));
		}

		data = (char)_Decode(pIndice, pShr, (int)sharedSecrets.size());
		pRecoverdSecret->Write(idx, &data, sizeof(char));
	}

	sha256((const unsigned char*)pRecoverdSecret->Buffer(), (unsigned int)pRecoverdSecret->Size(), tmp_hash_value);	
	if (memcmp(tmp_hash_value, hash_value, 32) != 0)
	{
		if (pRecoverdSecret != nullptr)
			delete pRecoverdSecret;

		if (pShr != nullptr)
			delete[] pShr;

		if (pIndice != nullptr)
			delete[] pIndice;

		return false;
	}

	recoverdSecrets.push_back(pRecoverdSecret);

	if (pShr != nullptr)
		delete[] pShr;

	if (pIndice != nullptr)
		delete[] pIndice;
	return true;
}

// math tools
Enco::uint32 DefaultSecretSharer::_Power(Enco::uint32 a, int b)
{
	//Enco::uint32 t = 1;
	Enco::int32 t = 1;
	
	int m = 0x0001;
	Enco::uint32 e = a;

	while (m != 0)
	{
		if (m & b)
		{
			t = _Multiply(t, e);
		}
		m = (m << 1) & 0x1FFFF;
		e = _Multiply(e, e);
	}

	return t;
}

Enco::uint32 DefaultSecretSharer::_Multiply(Enco::uint32 a, Enco::uint32 b)
{
	if (a > m_cnst_shamir_threshold)
	{
		Enco::uint64 alarge = a;
		Enco::uint64 blarge = b;

		return (alarge * blarge) % m_cnst_shamir_prime;
	}
	else
	{
		return (a * b) % m_cnst_shamir_prime;
	}
}

Enco::uint32 DefaultSecretSharer::_Sub(Enco::uint32 a, Enco::uint32 b)
{
	return (a - b + m_cnst_shamir_prime) % m_cnst_shamir_prime;
}

Enco::uint32 DefaultSecretSharer::_Add(Enco::uint32 a, Enco::uint32 b)
{
	return (a + b) % m_cnst_shamir_prime;
}

void DefaultSecretSharer::_SubRow(Enco::uint32 *from, Enco::uint32 *to, int k)
{
	int i;
	for (i = 0; i <= k; i++)
	{
		to[i] = _Sub(from[i], to[i]);
	}
}

void DefaultSecretSharer::_MulRow(Enco::uint32 *row, unsigned int a, int k)
{
	int i;
	for (i = 0; i <= k; i++)
	{
		row[i] = _Multiply(row[i], a);
	}
}

void DefaultSecretSharer::_SolveMatrix(Enco::uint32 **eqn, int k)
{
	int a, b;

	for (a = 0; a < k; a++)
	{
		for (b = 0; b < k; b++)
		{
			if (a == b)
			{
				continue;
			}

			Enco::uint32 c, o;

			c = eqn[a][a];
			o = eqn[b][a];

			_MulRow(eqn[a], o, k);
			_MulRow(eqn[b], c, k);

			_SubRow(eqn[a], eqn[b], k);
		}
	}
}

Enco::uint32 DefaultSecretSharer::_LinearSolve(Enco::uint32 a, Enco::uint32 b)
{
	Enco::uint32 inv = _Power(a, m_cnst_shamir_prime - 2);
	return _Multiply(inv, b);
}

Enco::uint32* DefaultSecretSharer::_Encode(Enco::uint32 secret, int n, int k, const Randomer& randomer, Enco::uint32 *shares)
{
	if (secret >= m_cnst_shamir_prime || secret < 0) { return NULL; }
	if (n >= m_cnst_shamir_prime || k > n) { return NULL; }
	if (shares == NULL) { return NULL; }

	Enco::uint32* c_buffer = new Enco::uint32[k];//malloc(sizeof(*c_buffer)*k);
	c_buffer[0] = secret;
	int c;
	for (c = 1; c < k; c++)
	{
		Enco::uint32 t;
		char random;
		random = (char)(randomer.Random());
		t = random;
		random = (char)(randomer.Random());
		t = (t << 8) ^ random;
		random = (char)(randomer.Random());
		t = (t << 8) ^ random;
		random = (char)(randomer.Random());
		t = (t << 8) ^ random;

		c_buffer[c] = t % m_cnst_shamir_prime;
	}

	int x;
	for (x = 1; x <= n; x++)
	{
		Enco::uint32 s = 0;
		int xp = 1;
		for (c = 0; c < k; c++)
		{
			s = _Add(s, _Multiply(c_buffer[c], xp));
			xp = _Multiply(xp, x);
		}
		shares[x - 1] = s;
	}
	delete[] c_buffer;

	return shares;
}

Enco::uint32 DefaultSecretSharer::_Decode(Enco::uint32 *x, Enco::uint32 *shares, int k)
{
	Enco::uint32 **eqn;
	Enco::uint32 *eqn_all;

	eqn = new Enco::uint32*[k];				// malloc(sizeof(*eqn) * k);
	eqn_all = new Enco::uint32[k*(k+1)];	// malloc(sizeof(*eqn_all) * k *(k + 1));

	int a;
	for (a = 0; a < k; a++)
	{
		eqn[a] = eqn_all + ((k + 1) * a);
	}

	int b;
	for (b = 0; b < k; b++)
	{
		Enco::uint32 xp = 1;
		Enco::uint32 xr = x[b];

		for (a = 0; a < k; a++)
		{
			eqn[b][a] = xp;
			xp = _Multiply(xp, xr);
		}
		eqn[b][k] = shares[b];
	}

	_SolveMatrix(eqn, k);
	return _LinearSolve(eqn[0][0], eqn[0][k]);
}

// //////////////////////////////////////////////////////////////////////////////////////////////
// DefaultStrongSSharer
DefaultStrongSSharer::DefaultStrongSSharer(const Randomer& randomer)
: DefaultSecretSharer(randomer)
{}

/*
* @implementation: Encode
* @description:
* @protocal:
*   ------------------------------------------
*   |  * GUID code      [ id bytes ]         |
*   |  * shared index   [  4 bytes ]         |
*   |  * sha256 value   [ 32 bytes ]         |
*   |  * secret data    [  x bytes ]         |
*   ------------------------------------------
*/
bool DefaultStrongSSharer::Encode(std::vector<FixedBuffer*>& sharedSecrets, const unsigned int& n, const unsigned int& k, const FixedBuffer& secretToShare)
{
	ReleaseSharedSecrets(sharedSecrets);
	std::vector<FixedBuffer*> originss;

	if (false == DefaultSecretSharer::Encode(originss, n, k, secretToShare))
	{
		ReleaseSharedSecrets(originss);
		return false;
	}

	GUID id;
	CoCreateGuid(&id);

	for (FixedBuffer* pSec : originss)
	{
		FixedBuffer* newss = new FixedBuffer(pSec->Size() + sizeof(GUID));
		newss->Write(0, &id, sizeof(GUID));

		newss->Write(sizeof(GUID), pSec->Buffer(), pSec->Size());
		sharedSecrets.push_back(newss);
	}

	return true;
}


/*
* @implementation: Decode
* @description:
* @protocal:
*   ------------------------------------------
*   |  * GUID code      [ id bytes ]         |
*   |  * shared index   [  4 bytes ]         |
*   |  * sha256 value   [ 32 bytes ]         |
*   |  * secret data    [  x bytes ]         |
*   ------------------------------------------
*/
bool DefaultStrongSSharer::Decode(std::vector<FixedBuffer*>& recoverdSecrets, const std::vector<FixedBuffer*>& sharedSecrets)
{
	std::unordered_map<GUID, std::vector<FixedBuffer*>*, Enco::guid_hash, Enco::guid_equal> ided_secs;

	for (FixedBuffer* pSecParts : sharedSecrets)
	{
		GUID tempID;

		pSecParts->Read(&tempID, 0, sizeof(GUID));
		if (ided_secs[tempID] == nullptr)
		{
			ided_secs[tempID] = new std::vector<FixedBuffer*>;
		}
		ided_secs[tempID]->push_back(pSecParts);
	}

	std::unordered_map<GUID, std::vector<FixedBuffer*>*, Enco::guid_hash, Enco::guid_equal>::const_iterator citer;
	for (citer = ided_secs.begin();
		citer != ided_secs.end();
		++citer)
	{
		std::vector<FixedBuffer*>	secgroup;

		for (auto& pSecs : *(citer->second))
		{
			FixedBuffer*	pUnpacked = new FixedBuffer(pSecs->Size() - sizeof(GUID));
			Enco::byte*		pStart = (Enco::byte*)pSecs->Buffer() + sizeof(GUID);
			pUnpacked->Write(0, pStart, pSecs->Size() - sizeof(GUID));
			secgroup.push_back(pUnpacked);
		}

		std::vector<FixedBuffer*>	recovered;		
		if (true != DefaultSecretSharer::Decode(recovered, secgroup))
		{
			ReleaseSharedSecrets(secgroup);
			ReleaseSharedSecrets(recovered);
			continue;
		}

		ReleaseSharedSecrets(secgroup);
		recoverdSecrets.push_back(recovered[0]);
	}

	return true;
}