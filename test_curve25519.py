import curve25519
import binascii
import unittest

class TestCurve25519(unittest.TestCase):

    def test_genkey(self):
        # implement mask checking here
        pass

    def test_public(self):
        pri1 = "a8abababababababababababababababababababababababababababababab6b".decode("hex")
        pri2 = "c8cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4d".decode("hex")

        pub1 = binascii.hexlify(bytearray(curve25519.public(pri1)))
        pub2 = binascii.hexlify(bytearray(curve25519.public(pri2)))

        self.assertEqual(pub1, "e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859")
        self.assertEqual(pub2, "b5bea823d9c9ff576091c54b7c596c0ae296884f0e150290e88455d7fba6126f")

    def test_shared_1(self):
        pri1 = "a8abababababababababababababababababababababababababababababab6b".decode("hex")
        pri2 = "c8cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4d".decode("hex")
        pub1 = "e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859".decode("hex")
        pub2 = "b5bea823d9c9ff576091c54b7c596c0ae296884f0e150290e88455d7fba6126f".decode("hex")

        shared1 = binascii.hexlify(bytearray(curve25519.shared(pri1, pub2)))
        shared2 = binascii.hexlify(bytearray(curve25519.shared(pri2, pub1)))

        self.assertEqual(shared1, shared2)
        self.assertEqual(shared1, "235101b705734aae8d4c2d9d0f1baf90bbb2a8c233d831a80d43815bb47ead10")

    def test_shared_2(self):
        for _ in range(100):
            pri1 = curve25519.genkey()
            pri2 = curve25519.genkey()
            pub1 = curve25519.public(pri1)
            pub2 = curve25519.public(pri2)
            shared1 = curve25519.shared(pri1, pub2)
            shared2 = curve25519.shared(pri2, pub1)
            self.assertEqual(shared1, shared2)

if __name__ == '__main__':
    unittest.main()
