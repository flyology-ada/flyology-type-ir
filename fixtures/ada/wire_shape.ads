package Wire_Shape is
   type Signed_16 is range -32_768 .. 32_767;
   type Unsigned_16 is mod 2 ** 16;

   type Public_Record is record
      Enabled  : Boolean;
      Signed   : Signed_16;
      Unsigned : Unsigned_16;
   end record;
end Wire_Shape;
