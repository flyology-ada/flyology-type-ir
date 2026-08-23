package Nested_Generics is
   type Actual is range 0 .. 100;

   generic
      type T is range <>;
   package Inner_Template is
      subtype Item is T;
   end Inner_Template;

   generic
      type U is range <>;
   package Outer_Template is
      package Inner_Instance is new Inner_Template (T => U);
   end Outer_Template;

   package Outer_Instance is new Outer_Template (U => Actual);
end Nested_Generics;
