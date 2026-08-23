package Constraints is
   Limit : Integer := 100;
   subtype Static_Range is Long_Long_Integer range
     -999_999_999_999_999_999 .. 999_999_999_999_999_999;
   subtype Dynamic_Range is Integer range 1 .. Limit;
end Constraints;
