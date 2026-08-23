with Ada.Command_Line;
with Ada.Text_IO;

procedure Flyology_Type_IR_Extract is
begin
   Ada.Text_IO.Put_Line
     (Ada.Text_IO.Standard_Error,
      "extractor traversal is not yet enabled; no IR was emitted");
   Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
end Flyology_Type_IR_Extract;
