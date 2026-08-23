package Demo is
   Zero : constant Integer := 0;
   subtype Small is Integer range 1 .. 10;
   type Packet (Kind : Integer) is record
      case Kind is
         when Zero | Small =>
            Payload : Integer;
            case Kind is
               when -1 + 1 =>
                  Nested_Payload : Integer;
               when others =>
                  null;
            end case;
         when 11 .. 20 =>
            null;
         when others =>
            null;
      end case;
   end record;
end Demo;
