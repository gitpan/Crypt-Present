# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Crypt-Present.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use strict;
use warnings;

use Test::More tests => 9;
BEGIN { use_ok('Crypt::Present') };

#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.



#     plaintext              key                ciphertext
# 00000000 00000000  00000000 00000000 0000  5579C138 7B228445
# 00000000 00000000  FFFFFFFF FFFFFFFF FFFF  E72C46C0 F5945049
# FFFFFFFF FFFFFFFF  00000000 00000000 0000  A112FFC7 2F68417B
# FFFFFFFF FFFFFFFF  FFFFFFFF FFFFFFFF FFFF  3333DCD3 213210D2

my @known = ( { KEY => ("\x00" x 10), PLAIN => ("\x00" x 8), CRYPT => pack('H*','5579C1387B228445') },
              { KEY => ("\x00" x 10), PLAIN => ("\xFF" x 8), CRYPT => pack('H*','A112FFC72F68417B') },
              { KEY => ("\xFF" x 10), PLAIN => ("\x00" x 8), CRYPT => pack('H*','E72C46C0F5945049') },
              { KEY => ("\xFF" x 10), PLAIN => ("\xFF" x 8), CRYPT => pack('H*','3333DCD3213210D2') },
            );
for my $known ( @known ) {
  my $cipher = new Crypt::Present( $known->{KEY} );
  my $plaintext  = $known->{PLAIN};
  my $crypttext  = $cipher->encrypt( $plaintext );
  my $plaintext2 = $cipher->decrypt( $crypttext );
  my $KEY_Hex   = unpack('H*',$known->{KEY});
  my $PLAIN_Hex = unpack('H*',$plaintext);
  my $CRYPT_Hex = unpack('H*',$known->{CRYPT});
  ok $plaintext eq $plaintext2, "KEY $KEY_Hex: decrypt( encrypt( $PLAIN_Hex} ) ) is ".unpack('H*',$plaintext2);
  ok $known->{CRYPT} eq $crypttext, "KEY $KEY_Hex: $PLAIN_Hex should -> $CRYPT_Hex and not ".unpack('H*',$crypttext);
}


#done_testing( 8 );

1;
