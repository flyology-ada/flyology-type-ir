package Views is
   type Secret is private;
   type Forward;
   type Forward_Access is access all Forward;
   type Forward is tagged null record;
private
   type Secret is record
      Value : Integer;
   end record;
end Views;
