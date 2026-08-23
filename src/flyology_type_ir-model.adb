with Ada.Characters.Handling;
with Ada.Numerics.Big_Numbers.Big_Integers;
with Ada.Strings.Fixed;

package body Flyology_Type_IR.Model is
   package Big_Integers renames Ada.Numerics.Big_Numbers.Big_Integers;
   use type Big_Integers.Big_Integer;

   function Fact_Key (Name : Fact_Name) return String is
   begin
      case Name is
         when Definite_Fact => return "definite";
         when Limited_Fact => return "limited";
         when Tagged_Fact => return "tagged";
         when Class_Wide_Fact => return "class_wide";
         when Abstract_Fact => return "abstract";
         when Contains_Access_Fact => return "contains_access";
         when Task_Fact => return "task";
         when Protected_Fact => return "protected";
         when Controlled_Fact => return "controlled";
         when Contains_Controlled_Fact => return "contains_controlled";
         when Aliased_Fact => return "aliased";
         when Constant_Fact => return "constant";
         when Predicate_Fact => return "predicate";
         when Constraint_Staticness_Fact => return "constraint_staticness";
         when Modulus_Fact => return "modulus";
         when Digits_Fact => return "digits";
         when Delta_Fact => return "delta";
         when Small_Fact => return "small";
         when Constrained_Fact => return "constrained";
         when Null_Exclusion_Fact => return "null_exclusion";
      end case;
   end Fact_Key;

   function Is_Canonical_Decimal (Value : String) return Boolean is
      First_Digit : Positive := Value'First;
   begin
      if Value'Length = 0 then
         return False;
      end if;

      if Value (Value'First) = '-' then
         if Value'Length = 1 then
            return False;
         end if;
         First_Digit := Value'First + 1;
      elsif Value (Value'First) = '+' then
         return False;
      end if;

      if Value (First_Digit) = '0' then
         return Value'Length = 1;
      end if;

      if Value (First_Digit) not in '1' .. '9' then
         return False;
      end if;

      for Position in First_Digit + 1 .. Value'Last loop
         if Value (Position) not in '0' .. '9' then
            return False;
         end if;
      end loop;
      return True;
   end Is_Canonical_Decimal;

   function Is_Valid_UTF8 (Value : String) return Boolean is
      Position : Integer := Value'First;
      Lead     : Natural;
      Next     : Natural;
      function Byte_At (Index : Integer) return Natural is
        (Standard.Character'Pos (Value (Index)));
      function Continuation (Byte : Natural) return Boolean is
        (Byte in 16#80# .. 16#BF#);
   begin
      while Position <= Value'Last loop
         Lead := Byte_At (Position);
         if Lead <= 16#7F# then
            Position := Position + 1;
         elsif Lead in 16#C2# .. 16#DF# then
            if Position + 1 > Value'Last
              or else not Continuation (Byte_At (Position + 1))
            then
               return False;
            end if;
            Position := Position + 2;
         elsif Lead in 16#E0# .. 16#EF# then
            if Position + 2 > Value'Last then
               return False;
            end if;
            Next := Byte_At (Position + 1);
            if not Continuation (Byte_At (Position + 2))
              or else (Lead = 16#E0# and then Next not in 16#A0# .. 16#BF#)
              or else (Lead = 16#ED# and then Next not in 16#80# .. 16#9F#)
              or else (Lead not in 16#E0# | 16#ED# and then not Continuation (Next))
            then
               return False;
            end if;
            Position := Position + 3;
         elsif Lead in 16#F0# .. 16#F4# then
            if Position + 3 > Value'Last then
               return False;
            end if;
            Next := Byte_At (Position + 1);
            if not Continuation (Byte_At (Position + 2))
              or else not Continuation (Byte_At (Position + 3))
              or else (Lead = 16#F0# and then Next not in 16#90# .. 16#BF#)
              or else (Lead = 16#F4# and then Next not in 16#80# .. 16#8F#)
              or else (Lead not in 16#F0# | 16#F4# and then not Continuation (Next))
            then
               return False;
            end if;
            Position := Position + 4;
         else
            return False;
         end if;
      end loop;
      return True;
   end Is_Valid_UTF8;

   function Is_Canonical_Name (Value : String) return Boolean is
      Segment_First : Positive := Value'First;

      function Valid_Segment (First, Last : Positive) return Boolean is
         Segment : constant String := Value (First .. Last);
         Reserved : constant Boolean :=
           Segment in
             "abort" | "abs" | "abstract" | "accept" | "access" | "aliased"
               | "all" | "and" | "array" | "at" | "begin" | "body" | "case"
               | "constant" | "declare" | "delay" | "delta" | "digits" | "do"
               | "else" | "elsif" | "end" | "entry" | "exception" | "exit"
               | "for" | "function" | "generic" | "goto" | "if" | "in"
               | "interface" | "is" | "limited" | "loop" | "mod" | "new"
               | "not" | "null" | "of" | "or" | "others" | "out"
               | "overriding" | "package" | "parallel" | "pragma" | "private"
               | "procedure" | "protected" | "raise" | "range" | "record"
               | "rem" | "renames" | "requeue" | "return" | "reverse"
               | "select" | "separate" | "some" | "subtype" | "synchronized"
               | "tagged" | "task" | "terminate" | "then" | "type" | "until"
               | "use" | "when" | "while" | "with" | "xor";
      begin
         if First > Last then
            return False;
         elsif Value (First) not in 'a' .. 'z' then
            return False;
         elsif Value (Last) = '_' or else Reserved then
            return False;
         end if;

         for Index in First + 1 .. Last loop
            if Value (Index) not in 'a' .. 'z'
              and then Value (Index) not in '0' .. '9'
              and then Value (Index) /= '_'
            then
               return False;
            elsif Value (Index) = '_' and then Value (Index - 1) = '_' then
               return False;
            end if;
         end loop;
         return True;
      end Valid_Segment;
   begin
      if Value'Length = 0 then
         return False;
      end if;
      for Position in Value'Range loop
         if Value (Position) = '.' then
            if Position = Segment_First
              or else not Valid_Segment (Segment_First, Position - 1)
            then
               return False;
            end if;
            Segment_First := Position + 1;
         end if;
      end loop;
      return Valid_Segment (Segment_First, Value'Last);
   end Is_Canonical_Name;

   function Is_Canonical_Semantic_ID (Value : String) return Boolean is
      use Ada.Characters.Handling;
      use Ada.Strings.Fixed;

      Suffix_Length : Natural := 0;
      Depth         : Natural := 0;

      function Has_Suffix (Suffix : String) return Boolean is
        (Value'Length >= Suffix'Length
         and then
           Value (Value'Last - Suffix'Length + 1 .. Value'Last) = Suffix);
   begin
      if Value'Length <= 5 or else Value (Value'First .. Value'First + 4) /= "decl:" then
         return False;
      end if;

      if Value /= To_Lower (Value)
        or else Index (Value, "file:") /= 0
        or else Index (Value, "\\") /= 0
      then
         return False;
      end if;

      if not (Has_Suffix ("#public")
              or else Has_Suffix ("#private")
              or else Has_Suffix ("#full")
              or else Has_Suffix ("#incomplete")
              or else Has_Suffix ("#class_wide"))
      then
         return False;
      end if;

      if Has_Suffix ("#public") then
         Suffix_Length := 7;
      elsif Has_Suffix ("#private") then
         Suffix_Length := 8;
      elsif Has_Suffix ("#full") then
         Suffix_Length := 5;
      else
         Suffix_Length := 11;
      end if;

      if Value'Length <= 5 + Suffix_Length then
         return False;
      end if;

      for Position in Value'First + 5 .. Value'Last - Suffix_Length loop
         case Value (Position) is
            when '[' =>
               if Position = Value'Last - Suffix_Length
                 or else Value (Position + 1) = ']'
               then
                  return False;
               end if;
               Depth := Depth + 1;
            when ']' =>
               if Depth = 0 then
                  return False;
               end if;
               Depth := Depth - 1;
            when '#' =>
               if Depth = 0 then
                  return False;
               end if;
            when others =>
               null;
         end case;
      end loop;
      if Depth /= 0 then
         return False;
      end if;

      for Character of Value loop
         if Character not in 'a' .. 'z'
           and then Character not in '0' .. '9'
           and then Character not in '.' | '_' | '=' | ',' | '[' | ']'
             | '#' | ':' | '-'
             | '%'
         then
            return False;
         end if;
      end loop;
      for Position in Value'Range loop
         if Value (Position) = '%'
           and then
             (Position + 2 > Value'Last
              or else Value (Position + 1) not in '0' .. '9' | 'a' .. 'f'
              or else Value (Position + 2) not in '0' .. '9' | 'a' .. 'f')
         then
            return False;
         end if;
      end loop;
      declare
         Position : Integer := Value'First;
         function Hex (Character : Standard.Character) return Natural is
           (if Character in '0' .. '9'
            then Standard.Character'Pos (Character)
              - Standard.Character'Pos ('0')
            else Standard.Character'Pos (Character)
              - Standard.Character'Pos ('a') + 10);
      begin
         while Position <= Value'Last loop
            if Value (Position) /= '%' then
               Position := Position + 1;
            else
               declare
                  Bytes : Text;
               begin
                  while Position <= Value'Last
                    and then Value (Position) = '%'
                  loop
                     US.Append
                       (Bytes,
                        Standard.Character'Val
                          (Hex (Value (Position + 1)) * 16
                           + Hex (Value (Position + 2))));
                     Position := Position + 3;
                  end loop;
                  if not Is_Valid_UTF8 (US.To_String (Bytes)) then
                     return False;
                  end if;
               end;
            end if;
         end loop;
      end;
      return True;
   end Is_Canonical_Semantic_ID;

   function Is_Well_Formed (Fact : Semantic_Fact) return Boolean is
      Has_Code  : constant Boolean := US.Length (Fact.Code) > 0;
      Value_OK  : Boolean;
      Code_OK   : Boolean := Has_Code;
   begin
      if not Is_Valid_UTF8 (US.To_String (Fact.Detail)) then
         return False;
      end if;
      if Has_Code then
         declare
            Code : constant String := US.To_String (Fact.Code);
         begin
            Code_OK := Code (Code'First) in 'a' .. 'z';
            for Character of Code loop
               Code_OK := Code_OK
                 and then
                   (Character in 'a' .. 'z'
                    or else Character in '0' .. '9'
                    or else Character in '.' | '_' | '-');
            end loop;
         end;
      end if;
      case Fact.Value.Kind is
         when Boolean_Value =>
            Value_OK := True;
         when Decimal_Integer_Value =>
            Value_OK := Is_Canonical_Decimal (US.To_String (Fact.Value.Decimal_Data));
         when Exact_Rational_Value =>
            declare
               Numerator_Image : constant String :=
                 US.To_String (Fact.Value.Numerator_Data);
               Denominator_Image : constant String :=
                 US.To_String (Fact.Value.Denominator_Data);
            begin
               Value_OK :=
                 Is_Canonical_Decimal (Numerator_Image)
                 and then Is_Canonical_Decimal (Denominator_Image)
                 and then Denominator_Image (Denominator_Image'First) /= '-'
                 and then Denominator_Image /= "0";
               if Value_OK then
                  declare
                     Numerator : constant Big_Integers.Valid_Big_Integer :=
                       Big_Integers.From_String (Numerator_Image);
                     Denominator : constant Big_Integers.Valid_Big_Integer :=
                       Big_Integers.From_String (Denominator_Image);
                     Zero : constant Big_Integers.Valid_Big_Integer :=
                       Big_Integers.To_Big_Integer (0);
                     One : constant Big_Integers.Valid_Big_Integer :=
                       Big_Integers.To_Big_Integer (1);
                  begin
                     Value_OK :=
                       (if Numerator = Zero
                        then Denominator = One
                        else Big_Integers.Greatest_Common_Divisor
                          (abs Numerator, Denominator) = One);
                  end;
               end if;
            end;
         when Text_Value =>
            Value_OK := Is_Valid_UTF8 (US.To_String (Fact.Value.Text_Data));
         when Expression_Value =>
            Value_OK := Fact.Value.Expression_Data /= null;
      end case;

      case Fact.Status is
         when Known =>
            return Value_OK and then not Has_Code;
         when Unknown | Unsupported =>
            return Code_OK
              and then Fact.Value.Kind = Text_Value
              and then US.Length (Fact.Value.Text_Data) = 0;
      end case;
   end Is_Well_Formed;

   function Is_Compatible
     (Name : Fact_Name;
      Fact : Semantic_Fact) return Boolean
   is
   begin
      if not Is_Well_Formed (Fact) then
         return False;
      elsif Fact.Status /= Known then
         return True;
      end if;

      case Name is
         when Definite_Fact
            | Limited_Fact
            | Tagged_Fact
            | Class_Wide_Fact
            | Abstract_Fact
            | Contains_Access_Fact
            | Task_Fact
            | Protected_Fact
            | Controlled_Fact
            | Contains_Controlled_Fact
            | Aliased_Fact
            | Constant_Fact
            | Predicate_Fact
            | Constraint_Staticness_Fact
            | Constrained_Fact
            | Null_Exclusion_Fact =>
            return Fact.Value.Kind = Boolean_Value;
         when Modulus_Fact | Digits_Fact =>
            return Fact.Value.Kind = Decimal_Integer_Value
              and then Big_Integers.From_String
                (US.To_String (Fact.Value.Decimal_Data))
                  > Big_Integers.To_Big_Integer (0);
         when Delta_Fact | Small_Fact =>
            return Fact.Value.Kind = Exact_Rational_Value
              and then Big_Integers.From_String
                (US.To_String (Fact.Value.Numerator_Data))
                  > Big_Integers.To_Big_Integer (0);
      end case;
   end Is_Compatible;

end Flyology_Type_IR.Model;
