package Generics is
   type Actual is range 0 .. 100;
   subtype Positive is Integer range 1 .. Integer'Last;
   generic
      type T is range <>;
      Limit : Integer;
   package Template is
      subtype Item is T range 0 .. T (Limit);
   end Template;
   package Instance is new Template (T => Actual, Limit => 42);

   procedure Do_Nothing (X : Integer);
   procedure Do_Nothing (X : Boolean);
   Actual_Object : Positive := 5;

   generic
      with package P is new Template (<>);
      with procedure Action (X : Integer);
      Obj : in out Integer;
      Defaulted : Integer := 7;
   package Mixed is
   end Mixed;

   package Mixed_Instance is new Mixed
     (Instance, Do_Nothing, Actual_Object);
end Generics;
