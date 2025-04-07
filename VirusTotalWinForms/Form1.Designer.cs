namespace VirusTotalWinForms
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            listBoxResults = new ListBox();
            button1 = new Button();
            button3 = new Button();
            SuspendLayout();
            // 
            // listBoxResults
            // 
            listBoxResults.FormattingEnabled = true;
            listBoxResults.ItemHeight = 15;
            listBoxResults.Location = new Point(12, 12);
            listBoxResults.Name = "listBoxResults";
            listBoxResults.Size = new Size(452, 634);
            listBoxResults.TabIndex = 0;
            // 
            // button1
            // 
            button1.BackColor = Color.YellowGreen;
            button1.Font = new Font("Segoe UI", 11F);
            button1.Location = new Point(504, 21);
            button1.Name = "button1";
            button1.Padding = new Padding(8);
            button1.RightToLeft = RightToLeft.Yes;
            button1.Size = new Size(132, 79);
            button1.TabIndex = 1;
            button1.Text = "Додати файл\r\n для перевірки ";
            button1.UseVisualStyleBackColor = false;
            button1.Click += button1_Click_1;
            // 
            // button3
            // 
            button3.BackColor = Color.Tomato;
            button3.Font = new Font("Segoe UI", 11F);
            button3.Location = new Point(504, 120);
            button3.Name = "button3";
            button3.Padding = new Padding(3);
            button3.RightToLeft = RightToLeft.Yes;
            button3.Size = new Size(132, 79);
            button3.TabIndex = 3;
            button3.Text = "Очистити файл з результатами";
            button3.UseVisualStyleBackColor = false;
            button3.Click += button3_Click;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            BackgroundImage = (Image)resources.GetObject("$this.BackgroundImage");
            BackgroundImageLayout = ImageLayout.Stretch;
            ClientSize = new Size(645, 667);
            Controls.Add(button3);
            Controls.Add(button1);
            Controls.Add(listBoxResults);
            DoubleBuffered = true;
            Name = "Form1";
            Text = "Form1";
            ResumeLayout(false);
        }

        #endregion

        private ListBox listBoxResults;
        private Button button1;
        private Button button3;
    }
}
