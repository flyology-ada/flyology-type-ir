package Shapes is
   function Identity (X : Integer) return Integer is (X);
   type Color is (Red, Green, Blue);
   type Vector is array (Integer range <>) of Integer;
   type Int_Access is access all Integer;
   type Float_6 is digits 6 range -1.0 .. 1.0;
   type Fixed_2 is delta 0.125 range -1.0 .. 1.0;
   type Decimal_2 is delta 0.01 digits 4 range -1.0 .. 1.0;
   type Mod_16 is mod 16;
   type Printable is interface;
   subtype Letter is Character range 'A' .. 'Z';

   type Holder (Count : Integer := 3) is record
      Value : Integer range 0 .. 10 := Count + 1;
   end record;

   type Container is record
      Items : Vector (1 .. 3);
      Data  : Holder (2);
   end record;
end Shapes;
