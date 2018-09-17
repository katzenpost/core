// cert_test.go - Certificate tests.
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cert

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/assert"
)

func TestExpiredCertificate(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration six months ago
	expiration := uint64(time.Now().AddDate(0, -6, 0).Unix() / hourSeconds)

	certificate, err := CreateCertificate(signingPrivKey, ephemeralPrivKey.PublicKey().Bytes(), "authority", expiration)
	assert.NoError(err)
	t.Logf("Certificate hex: %x", certificate)

	ok, err := VerifyCertificate(certificate, ephemeralPrivKey.PublicKey())
	assert.True(err != nil)
	assert.True(!ok)
}

func TestCertificate(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expires 600 years after unix epoch
	expiration := uint64(time.Unix(0, 0).AddDate(600, 0, 0).Unix() / hourSeconds)

	toSign := ephemeralPrivKey.PublicKey().Bytes()
	certificate, err := CreateCertificate(signingPrivKey, toSign, "authority", expiration)
	t.Logf("Certificate hex: %x, signing priv key %x data to sign %x", certificate, signingPrivKey.Bytes(), toSign)

	ok, err := VerifyCertificate(certificate, signingPrivKey.PublicKey())
	assert.NoError(err)
	assert.True(ok)
}

func TestBadCertificate(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration in six months
	expiration := uint64(time.Now().AddDate(0, 6, 0).Unix() / hourSeconds)

	certificate, err := CreateCertificate(signingPrivKey, ephemeralPrivKey.PublicKey().Bytes(), "authority", expiration)
	assert.NoError(err)
	t.Logf("Certificate hex: %x", certificate)

	ok, err := VerifyCertificate(certificate, ephemeralPrivKey.PublicKey())
	assert.NoError(err)
	assert.True(!ok)
}

func TestMultiSignatureCertificate(t *testing.T) {
	assert := assert.New(t)

	ephemeralPrivKey, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	signingPrivKey1, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey2, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)
	signingPrivKey3, err := eddsa.NewKeypair(rand.Reader)
	assert.NoError(err)

	// expiration in six months
	expiration := uint64(time.Now().AddDate(0, 6, 0).Unix() / hourSeconds)

	certificate, err := CreateCertificate(signingPrivKey1, ephemeralPrivKey.PublicKey().Bytes(), "authority", expiration)
	assert.NoError(err)
	t.Logf("Certificate hex: %x", certificate)

	certificate, err = SignMultiCertificate(signingPrivKey2, certificate)
	assert.NoError(err)

	certificate, err = SignMultiCertificate(signingPrivKey3, certificate)
	assert.NoError(err)

	ok, err := VerifyMulti(certificate, signingPrivKey1.PublicKey())
	assert.NoError(err)
	assert.True(ok)

	ok, err = VerifyMulti(certificate, signingPrivKey2.PublicKey())
	assert.NoError(err)
	assert.True(ok)

	ok, err = VerifyMulti(certificate, signingPrivKey3.PublicKey())
	assert.NoError(err)
	assert.True(ok)
}

type inTest struct {
	signingKey string
	toSign     string
}

type outTest struct {
	payload string
}

func TestSingleSignatureCertificateVectors(t *testing.T) {
	assert := assert.New(t)

	certificateTests := []struct {
		in   inTest
		want outTest
	}{
		{
			inTest{
				signingKey: "e818ee275ddb72b8e63758dfba3a90e0f5687dd59f28c2812e9861ba19fa33bffb731cf47b3732b24a5f9c00a0304b66d461b23e7292c5eb406ec09adc2d95e0",
				toSign:     "32d4f52620a57aa2b02564c296c0b4b0dbeca5471704a9f40000706bcc134d2f",
			}, outTest{
				payload: "a66b436572744b657954797065676564323535313969436572746966696564582032d4f52620a57aa2b02564c296c0b4b0dbeca5471704a9f40000706bcc134d2f6a45787069726174696f6e1a005040f06a5369676e61747572657381a2684964656e746974795820fb731cf47b3732b24a5f9c00a0304b66d461b23e7292c5eb406ec09adc2d95e0675061796c6f6164584095bf110e7757ad24ff03c134a9bfbffff8845b4f304f6a90c36d04150c9b194d450040dc8103e72ef277c181350150e288fb26669a3d1b33dd736637b2311a0d645479706569617574686f726974796756657273696f6e00",
			},
		},
		{
			inTest{
				signingKey: "f99bdb809088a609c270f612a0e44844d03d86a63e109966ca66f6678cc02a1065efbc72434d921af5285c0fd28af6ed8592c0ac44c834d9d98f5589ea21c03f",
				toSign:     "ea7b8ef81c91986d93f0532c1de06ce25373c20782d8106ac6a4d85eee4802bb",
			}, outTest{
				payload: "a66b436572744b6579547970656765643235353139694365727469666965645820ea7b8ef81c91986d93f0532c1de06ce25373c20782d8106ac6a4d85eee4802bb6a45787069726174696f6e1a005040f06a5369676e61747572657381a2684964656e74697479582065efbc72434d921af5285c0fd28af6ed8592c0ac44c834d9d98f5589ea21c03f675061796c6f6164584035331c16e3718a4e3f45f4026b5d4a0589a7aae945fa7114501e0742b507c80a07971d6f1d74c34010e24b87da3832928d2987fad1bfcd06b4deb4ad08d25304645479706569617574686f726974796756657273696f6e00",
			},
		},
		{
			inTest{
				signingKey: "13a40a6146651427a769e3dd17dc86d4497f5379aa077488fc8d40ce062675bf39b956e6aae2b76a13dd83c0eb96c3e2b22e6ad4e944625a7c0230b4561b82d9",
				toSign:     "220b7f2efa95f089a75711aad6c843d9899af3e622f7adf06da6d7264ed0ece5093f423dc1fb5d1672643fa133680e49ce74ad5c0367ba0aee902b41a2ad3e9ffbb8db5503b33f0ae61ca28a01bf1b8615d8c2c5f9ac02572e89c76aef5c8b00c052ba4b13ef043fc9f39b90eed1e2e9bccc06a67d3cde025e0b7cfc15cc3efacc50b7bbc525e02f5c52f920b9e03bef07b320f37347359888feaed0ab4d83e0cc6877f00162b3ac424df7cee0b47f1a9f00d49651c2982e59504c889182cda7130e7f83949e193f",
			}, outTest{
				payload: "a66b436572744b65795479706567656432353531396943657274696669656458c8220b7f2efa95f089a75711aad6c843d9899af3e622f7adf06da6d7264ed0ece5093f423dc1fb5d1672643fa133680e49ce74ad5c0367ba0aee902b41a2ad3e9ffbb8db5503b33f0ae61ca28a01bf1b8615d8c2c5f9ac02572e89c76aef5c8b00c052ba4b13ef043fc9f39b90eed1e2e9bccc06a67d3cde025e0b7cfc15cc3efacc50b7bbc525e02f5c52f920b9e03bef07b320f37347359888feaed0ab4d83e0cc6877f00162b3ac424df7cee0b47f1a9f00d49651c2982e59504c889182cda7130e7f83949e193f6a45787069726174696f6e1a005040f06a5369676e61747572657381a2684964656e74697479582039b956e6aae2b76a13dd83c0eb96c3e2b22e6ad4e944625a7c0230b4561b82d9675061796c6f616458408731f27095989c6947bc67c839d0e63d3d0a513acfdc911656515161756114ee1246b303a3b482fc72da8db578840fb9999f3b95243fd22bc00192d840bb2606645479706569617574686f726974796756657273696f6e00",
			},
		},
	}

	for _, test := range certificateTests {
		// expires 600 years after unix epoch
		expiration := uint64(time.Unix(18934214400, 0).Unix() / hourSeconds)
		signingKeyRaw, err := hex.DecodeString(test.in.signingKey)
		assert.NoError(err)
		toSign, err := hex.DecodeString(test.in.toSign)
		assert.NoError(err)
		signingKey := new(eddsa.PrivateKey)
		signingKey.FromBytes(signingKeyRaw)
		certificate, err := CreateCertificate(signingKey, toSign, "authority", expiration)
		assert.NoError(err)
		payload, err := hex.DecodeString(test.want.payload)
		assert.NoError(err)
		assert.Equal(certificate, payload)
	}
}

type multiSigTest struct {
	signingKeys []string
	toSign      string
}

func TestMultipleSignatureCertificateVectors(t *testing.T) {
	assert := assert.New(t)

	certificateTests := []struct {
		in   multiSigTest
		want outTest
	}{
		{
			multiSigTest{
				signingKeys: []string{
					"e818ee275ddb72b8e63758dfba3a90e0f5687dd59f28c2812e9861ba19fa33bffb731cf47b3732b24a5f9c00a0304b66d461b23e7292c5eb406ec09adc2d95e0",
					"f99bdb809088a609c270f612a0e44844d03d86a63e109966ca66f6678cc02a1065efbc72434d921af5285c0fd28af6ed8592c0ac44c834d9d98f5589ea21c03f",
				},
				toSign: "32d4f52620a57aa2b02564c296c0b4b0dbeca5471704a9f40000706bcc134d2f",
			}, outTest{
				payload: "a66b436572744b657954797065676564323535313969436572746966696564582032d4f52620a57aa2b02564c296c0b4b0dbeca5471704a9f40000706bcc134d2f6a45787069726174696f6e1a005040f06a5369676e61747572657383a2684964656e746974795820fb731cf47b3732b24a5f9c00a0304b66d461b23e7292c5eb406ec09adc2d95e0675061796c6f6164584095bf110e7757ad24ff03c134a9bfbffff8845b4f304f6a90c36d04150c9b194d450040dc8103e72ef277c181350150e288fb26669a3d1b33dd736637b2311a0da2684964656e746974795820fb731cf47b3732b24a5f9c00a0304b66d461b23e7292c5eb406ec09adc2d95e0675061796c6f6164584095bf110e7757ad24ff03c134a9bfbffff8845b4f304f6a90c36d04150c9b194d450040dc8103e72ef277c181350150e288fb26669a3d1b33dd736637b2311a0da2684964656e74697479582065efbc72434d921af5285c0fd28af6ed8592c0ac44c834d9d98f5589ea21c03f675061796c6f61645840880a9ee1d6b07fa31fa9620cf61d267ad71dcd9a806697f55eff0ef899b0377a9e10e1e70620b21b1ca00d2f64445dba88acbe1368e73765e2b4bad54585dd0f645479706569617574686f726974796756657273696f6e00",
			},
		},
		{
			multiSigTest{
				signingKeys: []string{
					"e818ee275ddb72b8e63758dfba3a90e0f5687dd59f28c2812e9861ba19fa33bffb731cf47b3732b24a5f9c00a0304b66d461b23e7292c5eb406ec09adc2d95e0",
					"f99bdb809088a609c270f612a0e44844d03d86a63e109966ca66f6678cc02a1065efbc72434d921af5285c0fd28af6ed8592c0ac44c834d9d98f5589ea21c03f",
					"13a40a6146651427a769e3dd17dc86d4497f5379aa077488fc8d40ce062675bf39b956e6aae2b76a13dd83c0eb96c3e2b22e6ad4e944625a7c0230b4561b82d9",
				},
				toSign: "32d4f52620a57aa2b02564c296c0b4b0dbeca5471704a9f40000706bcc134d2f",
			}, outTest{
				payload: "a66b436572744b657954797065676564323535313969436572746966696564582032d4f52620a57aa2b02564c296c0b4b0dbeca5471704a9f40000706bcc134d2f6a45787069726174696f6e1a005040f06a5369676e61747572657384a2684964656e746974795820fb731cf47b3732b24a5f9c00a0304b66d461b23e7292c5eb406ec09adc2d95e0675061796c6f6164584095bf110e7757ad24ff03c134a9bfbffff8845b4f304f6a90c36d04150c9b194d450040dc8103e72ef277c181350150e288fb26669a3d1b33dd736637b2311a0da2684964656e746974795820fb731cf47b3732b24a5f9c00a0304b66d461b23e7292c5eb406ec09adc2d95e0675061796c6f6164584095bf110e7757ad24ff03c134a9bfbffff8845b4f304f6a90c36d04150c9b194d450040dc8103e72ef277c181350150e288fb26669a3d1b33dd736637b2311a0da2684964656e74697479582065efbc72434d921af5285c0fd28af6ed8592c0ac44c834d9d98f5589ea21c03f675061796c6f61645840880a9ee1d6b07fa31fa9620cf61d267ad71dcd9a806697f55eff0ef899b0377a9e10e1e70620b21b1ca00d2f64445dba88acbe1368e73765e2b4bad54585dd0fa2684964656e74697479582039b956e6aae2b76a13dd83c0eb96c3e2b22e6ad4e944625a7c0230b4561b82d9675061796c6f616458408775162ce2fd87bbcb9b81c4c612b6cefbbd32a735cb820ae98e5d3d2db867d626e0d897d9f291cac1d199be26ecd9ddd2580380d366dc62a3cb97ed86281b05645479706569617574686f726974796756657273696f6e00",
			},
		},
		{
			multiSigTest{
				signingKeys: []string{
					"b82b2fbb1fa8fbf771dc85dc45e66a1626d44cf3361f3a61e387b266445346dec57a0f83107b9ded621900615ca8ad5fda6f7bc839fb0fbf6f4b6af59611c710",
					"4b888f00728a6b7594f8eb6440e4a084889017d2d520ac7b3a8d0b5030872329d12f2a5061f93b378b94f72ddb2082e3e18681d902d4c65ae95c41001e8821be",
					"e5ac1b84e158d06ace83947a5fba08af9b000d195503dae4d4a9728b5c0cef9ae896881e859d836443a4c6dfb7fbd3cd07160065b8eb000a4297c7c5c194e287",
					"e66cc68c6606f1072485164e6ff989abaf1cef493ba25e922bbcb601769dc4dca3bfdb632fdc227a276e17b2b573d31c7e6bbb236c25af5c5ffde17139d9e4bd",
				},
				toSign: "2f15f386b80725ad11e1b2b55b53eeaea003a6cc6e5c359f344fb7af6f39dc043140578009262ea3247aef5e84c0a79e5962506185b54601b93d6d53bdc64dbcb27543657d2229096276a0e677f61cff7cb7c04bfc453b377bc780acb3163346cf3bcaffd0355ca29a6e47a981d85631b6c7c4bef767502d6982dc176df9776b217c2fe62886b139e48ea658c9aa450d995cc6d1bae5a220187694d120fa43fc77be3b3e57ea1a2d1f4247e6a580b8529063eb5dc44c5d64bab43474c66994bb36d149dfee4660ce5e1b8dc9edf8ca407a21519ecfdda6e7c3c3fd83257dc77e02f9c20cc1d68f56255a8e7147b3b6b334039d520215b5d219e899ebd454f3ba1f502f2b9710cc4cde4ec09d6ece17c19ee101eb42459cd3dfc1d7de76b58d4b0fed25335cb0756ea7eb2e762bc139ab8ec7ac8ea4240e034a95011649c5f856ed49e803f41e846a9043b320690b272d3b236af33e8a7d5fbb08a62edca052a58db32143c7b290a129303633ba944f5b9b66ce0123428bb20e7d8d26fb24bf0f5c2fa72a703d8bd31756ae540d887529832e48d8780efcab4e5c2cb59c89d853905562fd76920fd53f415e9cbdb6417a89de8b6ecf71051e877f2a230cee85b150f1479573b01ee7e486e2240b104df54f1dcfb469b946a6547eab1c32631d4171eb008d829231ce18155391570de540b1872a42c8547550f4b53a27430afa517784f32f849181243fc1ba3781caa4031829d491aa9b094ec6516c96880b013a25e4c94ad127452c0df9bd3ddb7eb108a7bfe65fee0626097c55c9a4ff55ac1a6ba5b85ae13408cb5d3e9a64bfbaa1848112f95ffc409229928ebcedde1ff4379ce69141d95dfc1fb10466d6fdfbeee2cccf961b71f2c59824ad43bf05ca9b0d5e48182f83cc61671354c72dfffb4a755cc44d3bd959078078a84ebfcf5a3817e820809ed87eb8d66adc5da1d55c33d8cb882f39f06590cbb9a52f21",
			}, outTest{
				payload: "a66b436572744b6579547970656765643235353139694365727469666965645902bc2f15f386b80725ad11e1b2b55b53eeaea003a6cc6e5c359f344fb7af6f39dc043140578009262ea3247aef5e84c0a79e5962506185b54601b93d6d53bdc64dbcb27543657d2229096276a0e677f61cff7cb7c04bfc453b377bc780acb3163346cf3bcaffd0355ca29a6e47a981d85631b6c7c4bef767502d6982dc176df9776b217c2fe62886b139e48ea658c9aa450d995cc6d1bae5a220187694d120fa43fc77be3b3e57ea1a2d1f4247e6a580b8529063eb5dc44c5d64bab43474c66994bb36d149dfee4660ce5e1b8dc9edf8ca407a21519ecfdda6e7c3c3fd83257dc77e02f9c20cc1d68f56255a8e7147b3b6b334039d520215b5d219e899ebd454f3ba1f502f2b9710cc4cde4ec09d6ece17c19ee101eb42459cd3dfc1d7de76b58d4b0fed25335cb0756ea7eb2e762bc139ab8ec7ac8ea4240e034a95011649c5f856ed49e803f41e846a9043b320690b272d3b236af33e8a7d5fbb08a62edca052a58db32143c7b290a129303633ba944f5b9b66ce0123428bb20e7d8d26fb24bf0f5c2fa72a703d8bd31756ae540d887529832e48d8780efcab4e5c2cb59c89d853905562fd76920fd53f415e9cbdb6417a89de8b6ecf71051e877f2a230cee85b150f1479573b01ee7e486e2240b104df54f1dcfb469b946a6547eab1c32631d4171eb008d829231ce18155391570de540b1872a42c8547550f4b53a27430afa517784f32f849181243fc1ba3781caa4031829d491aa9b094ec6516c96880b013a25e4c94ad127452c0df9bd3ddb7eb108a7bfe65fee0626097c55c9a4ff55ac1a6ba5b85ae13408cb5d3e9a64bfbaa1848112f95ffc409229928ebcedde1ff4379ce69141d95dfc1fb10466d6fdfbeee2cccf961b71f2c59824ad43bf05ca9b0d5e48182f83cc61671354c72dfffb4a755cc44d3bd959078078a84ebfcf5a3817e820809ed87eb8d66adc5da1d55c33d8cb882f39f06590cbb9a52f216a45787069726174696f6e1a005040f06a5369676e61747572657385a2684964656e746974795820c57a0f83107b9ded621900615ca8ad5fda6f7bc839fb0fbf6f4b6af59611c710675061796c6f61645840a55ea60e293add5059719f6207e27f58e60e4336e5cf5069215ec4ea96aac4e9b072a33e6c31d63dcbb5de5709ec86eb92098576aa6c1029da9857e50040f509a2684964656e746974795820c57a0f83107b9ded621900615ca8ad5fda6f7bc839fb0fbf6f4b6af59611c710675061796c6f61645840a55ea60e293add5059719f6207e27f58e60e4336e5cf5069215ec4ea96aac4e9b072a33e6c31d63dcbb5de5709ec86eb92098576aa6c1029da9857e50040f509a2684964656e746974795820d12f2a5061f93b378b94f72ddb2082e3e18681d902d4c65ae95c41001e8821be675061796c6f6164584006f739c76a707614bac6860c20d271f52e9330ca24e98d7bfc4001b7342eb289c35fb982395c32eabaf43d84999aa5101aa15fa96f49b3bcfd9815f6093c9e04a2684964656e746974795820e896881e859d836443a4c6dfb7fbd3cd07160065b8eb000a4297c7c5c194e287675061796c6f61645840d0383495e51cfc507eab922303c2e43a9b7d144c759f1b09afac49f5fcc75eb10512ea925a2abc04bc3606927b530189ebf5818bfe1c96c7c324c994fc5f8400a2684964656e746974795820a3bfdb632fdc227a276e17b2b573d31c7e6bbb236c25af5c5ffde17139d9e4bd675061796c6f61645840447e96a581b1c1d62627255c29e3d77d8112c697d2104d12c403a4b55bf05705415f9f97d465d7e23bdc715507bddea79ff6bbcfaf03ae04acb2c755b6ea1503645479706569617574686f726974796756657273696f6e00",
			},
		},
	}

	for _, test := range certificateTests {
		// expires 600 years after unix epoch
		expiration := uint64(time.Unix(18934214400, 0).Unix() / hourSeconds)

		sigKeys := []*eddsa.PrivateKey{}
		for _, key := range test.in.signingKeys {
			signingKeyRaw, err := hex.DecodeString(key)
			assert.NoError(err)
			signingKey := new(eddsa.PrivateKey)
			signingKey.FromBytes(signingKeyRaw)
			sigKeys = append(sigKeys, signingKey)
		}

		toSign, err := hex.DecodeString(test.in.toSign)
		assert.NoError(err)
		certificate, err := CreateCertificate(sigKeys[0], toSign, "authority", expiration)
		assert.NoError(err)
		for _, signingKey := range sigKeys {
			certificate, err = SignMultiCertificate(signingKey, certificate)
			assert.NoError(err)
		}
		payload, err := hex.DecodeString(test.want.payload)
		assert.NoError(err)
		assert.Equal(certificate, payload)
	}
}
