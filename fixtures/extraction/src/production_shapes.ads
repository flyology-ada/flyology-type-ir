package Production_Shapes is
   type Position is (First, Second, Third);
   type Color is (Red, Green, Blue);
   type Palette is array (Position) of Color;

   type Packet is record
      Shade   : Color;
      Samples : Palette;
   end record;
end Production_Shapes;
