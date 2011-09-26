/*
Copyright (C) Max Kastanas 2010

 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#import "FwknopController.h"

@implementation EditableViewController

@synthesize itemValue = _itemValue;



- (void)loadView
{
    [super loadView];
    
    CGFloat margin = 20.0;
    
    CGRect viewRect = { margin, 40.0, 280.0, 400.0  };
    UIView *view = [[UIView alloc] initWithFrame:viewRect];
    [view setBackgroundColor:[UIColor lightGrayColor]];
    [view setOpaque:YES];
    [self setView:view];
        
	//HEADER
    CGRect labelHeaderRect = { margin + 60, 15.0, 120.0, 28.0 };
    UILabel *labelHeader = [[UILabel alloc] initWithFrame:labelHeaderRect];
    [labelHeader setBackgroundColor:[UIColor lightGrayColor]];
    [labelHeader setTextColor:[UIColor darkGrayColor]];
    [labelHeader setFont:[UIFont boldSystemFontOfSize:16.0]];
    [labelHeader setOpaque:YES];
    [labelHeader setText:@"Fwknop Client"];
    [view addSubview:labelHeader];
	
	//allow ip
    CGRect labelRect = { margin, 50.0, 120.0, 28.0 };
    UILabel *label = [[UILabel alloc] initWithFrame:labelRect];
    [label setBackgroundColor:[UIColor lightGrayColor]];
    [label setTextColor:[UIColor darkGrayColor]];
    [label setFont:[UIFont boldSystemFontOfSize:16.0]];
    [label setOpaque:YES];
    [label setText:@"Allow IP:"];
    [view addSubview:label];
    
    CGRect textFieldRect = { margin + 120, 50.0, 120.0, 28.0 };
    UITextField *textField = [[UITextField alloc] initWithFrame:textFieldRect];
    [textField setBackgroundColor:[UIColor whiteColor]];
    [textField setBorderStyle:UITextBorderStyleBezel];
    [textField setOpaque:YES];
    [textField setPlaceholder:@"0.0.0.0"];
	[textField setText:@"0.0.0.0"];
    //[textField setReturnKeyType:UIReturnKeyDone];
    //[textField setEnablesReturnKeyAutomatically:YES];
    [textField setTag:1];
    [textField setDelegate:self];
    [view addSubview:textField];
    
	//access protocol
	CGRect labelAccessProtoRect = { margin, 85.0, 120.0, 28.0 };
    UILabel *labelAccessProto = [[UILabel alloc] initWithFrame:labelAccessProtoRect];
    [labelAccessProto setBackgroundColor:[UIColor lightGrayColor]];
    [labelAccessProto setTextColor:[UIColor darkGrayColor]];
    [labelAccessProto setFont:[UIFont boldSystemFontOfSize:16.0]];
    [labelAccessProto setOpaque:YES];
    [labelAccessProto setText:@"Access Protocol:"];
    [view addSubview:labelAccessProto];
    
    CGRect textFieldAccessProtoRect = { margin + 120, 85.0, 120.0, 28.0 };
    UITextField *textFieldAccessProto = [[UITextField alloc] initWithFrame:textFieldAccessProtoRect];
    [textFieldAccessProto setBackgroundColor:[UIColor whiteColor]];
    [textFieldAccessProto setBorderStyle:UITextBorderStyleBezel];
    [textFieldAccessProto setOpaque:YES];
    [textFieldAccessProto setPlaceholder:@"tcp/udp"];
	[textFieldAccessProto setText:@"tcp"];
    [textFieldAccessProto setReturnKeyType:UIReturnKeyDone];
    [textFieldAccessProto setEnablesReturnKeyAutomatically:YES];
    [textFieldAccessProto setTag:4];
    [textFieldAccessProto setDelegate:self];
    [view addSubview:textFieldAccessProto];
	
	//access port
	CGRect labelAccessPortRect = { margin, 120.0, 120.0, 28.0 };
    UILabel *labelAccessPort = [[UILabel alloc] initWithFrame:labelAccessPortRect];
    [labelAccessPort setBackgroundColor:[UIColor lightGrayColor]];
    [labelAccessPort setTextColor:[UIColor darkGrayColor]];
    [labelAccessPort setFont:[UIFont boldSystemFontOfSize:16.0]];
    [labelAccessPort setOpaque:YES];
    [labelAccessPort setText:@"Access Port:"];
    [view addSubview:labelAccessPort];
    
    CGRect textFieldAccessPortRect = { margin + 120, 120.0, 120.0, 28.0 };
    UITextField *textFieldAccessPort = [[UITextField alloc] initWithFrame:textFieldAccessPortRect];
    [textFieldAccessPort setBackgroundColor:[UIColor whiteColor]];
    [textFieldAccessPort setBorderStyle:UITextBorderStyleBezel];
    [textFieldAccessPort setOpaque:YES];
    [textFieldAccessPort setPlaceholder:@"22"];
    [textFieldAccessPort setText:@"22"];
	[textFieldAccessPort setReturnKeyType:UIReturnKeyDone];
    [textFieldAccessPort setEnablesReturnKeyAutomatically:YES];
    [textFieldAccessPort setTag:5];
    [textFieldAccessPort setDelegate:self];
    [view addSubview:textFieldAccessPort];
	
	//Server Address
	CGRect labelServerAddrRect = { margin, 155.0, 120.0, 28.0 };
    UILabel *labelServerAddr = [[UILabel alloc] initWithFrame:labelServerAddrRect];
    [labelServerAddr setBackgroundColor:[UIColor lightGrayColor]];
    [labelServerAddr setTextColor:[UIColor darkGrayColor]];
    [labelServerAddr setFont:[UIFont boldSystemFontOfSize:16.0]];
    [labelServerAddr setOpaque:YES];
    [labelServerAddr setText:@"Server Address"];
    [view addSubview:labelServerAddr];
    
    CGRect textFieldServerAddrRect = { margin + 120, 155.0, 120.0, 28.0 };
    UITextField *textFieldServerAddr = [[UITextField alloc] initWithFrame:textFieldServerAddrRect];
    [textFieldServerAddr setBackgroundColor:[UIColor whiteColor]];
    [textFieldServerAddr setBorderStyle:UITextBorderStyleBezel];
    [textFieldServerAddr setOpaque:YES];
    [textFieldServerAddr setPlaceholder:@"Server"];
    [textFieldServerAddr setText:@""];
	[textFieldServerAddr setReturnKeyType:UIReturnKeyDone];
    [textFieldServerAddr setEnablesReturnKeyAutomatically:YES];
    [textFieldServerAddr setTag:6];
    [textFieldServerAddr setDelegate:self];
    [view addSubview:textFieldServerAddr];

	//Rijndael key
	CGRect labelRijndaelKeyRect = { margin, 190.0, 120.0, 28.0 };
    UILabel *labelRijndaelKey = [[UILabel alloc] initWithFrame:labelRijndaelKeyRect];
    [labelRijndaelKey setBackgroundColor:[UIColor lightGrayColor]];
    [labelRijndaelKey setTextColor:[UIColor darkGrayColor]];
    [labelRijndaelKey setFont:[UIFont boldSystemFontOfSize:16.0]];
    [labelRijndaelKey setOpaque:YES];
    [labelRijndaelKey setText:@"Rijndael Key:"];
    [view addSubview:labelRijndaelKey];
    
    CGRect textFieldRijndaelKeyRect = { margin + 120, 190.0, 120.0, 28.0 };
    UITextField *textFieldRijndaelKey = [[UITextField alloc] initWithFrame:textFieldRijndaelKeyRect];
    [textFieldRijndaelKey setBackgroundColor:[UIColor whiteColor]];
    [textFieldRijndaelKey setBorderStyle:UITextBorderStyleBezel];
    [textFieldRijndaelKey setOpaque:YES];
    [textFieldRijndaelKey setPlaceholder:@"Key"];
	[textFieldRijndaelKey setText:@""];
	[textFieldRijndaelKey setSecureTextEntry:YES];
    [textFieldRijndaelKey setReturnKeyType:UIReturnKeyDone];
    [textFieldRijndaelKey setEnablesReturnKeyAutomatically:YES];
    [textFieldRijndaelKey setTag:7];
    [textFieldRijndaelKey setDelegate:self];
    [view addSubview:textFieldRijndaelKey];

	//Rijndael key
	CGRect labelTimeoutRect = { margin, 225.0, 120.0, 28.0 };
    UILabel *labelTimeout = [[UILabel alloc] initWithFrame:labelTimeoutRect];
    [labelTimeout setBackgroundColor:[UIColor lightGrayColor]];
    [labelTimeout setTextColor:[UIColor darkGrayColor]];
    [labelTimeout setFont:[UIFont boldSystemFontOfSize:16.0]];
    [labelTimeout setOpaque:YES];
    [labelTimeout setText:@"Timeout: "];
    [view addSubview:labelTimeout];
    
    CGRect textFieldTimeoutRect = { margin + 120, 225.0, 120.0, 28.0 };
    UITextField *textFieldTimeout = [[UITextField alloc] initWithFrame:textFieldTimeoutRect];
    [textFieldTimeout setBackgroundColor:[UIColor whiteColor]];
    [textFieldTimeout setBorderStyle:UITextBorderStyleBezel];
    [textFieldTimeout setOpaque:YES];
    [textFieldTimeout setPlaceholder:@"timeout"];
	[textFieldTimeout setText:@"60"];
    [textFieldTimeout setReturnKeyType:UIReturnKeyDone];
    [textFieldTimeout setEnablesReturnKeyAutomatically:YES];
    [textFieldTimeout setTag:8];
    [textFieldTimeout setDelegate:self];
    [view addSubview:textFieldTimeout];
	
	//Status
    CGRect labelRect2 = { margin, 300.0, 120.0, 24.0 };
    UILabel *label2 = [[UILabel alloc] initWithFrame:labelRect2];
    [label2 setBackgroundColor:[UIColor lightGrayColor]];
    [label2 setOpaque:YES];
    [label2 setTextColor:[UIColor grayColor]];
    [label2 setText:@"Status:"];
    [view addSubview:label2];
    
    CGRect textFieldRect2 = { 135.0, 302.0, 120.0, 28.0 };
    UITextField *textField2 = [[UITextField alloc] initWithFrame:textFieldRect2];
    [textField2 setBackgroundColor:[UIColor lightGrayColor]];
    [textField2 setTextColor:[UIColor grayColor]];
    [textField2 setEnabled:NO];
    [textField2 setBorderStyle:UITextBorderStyleNone];
    [textField2 setOpaque:YES];
	[textField2 setText:@""];
    [textField2 setTag:2];
    [view addSubview:textField2];
	
	//Send SPA
    CGFloat width = 60.0;
    CGFloat x = [view center].x - (width / 2.0) - (margin / 2.0);
    CGRect buttonRect = { x, 360.0, width, 24.0 };
    UIButton *button = [UIButton buttonWithType:UIButtonTypeRoundedRect];
    [button setFrame:buttonRect];
    [button setTitle:@"Send" forState:UIControlStateNormal];
    [button addTarget:self
               action:@selector(save)
     forControlEvents:UIControlEventTouchUpInside];
    [view addSubview:button];
    
    [view release];
    [label release];
    [textField release];
}

int sendSPA(NSString * allowip, NSString * proto, 
			NSString * port, NSString * server, 
			NSString * key, NSString * timeout){
	
	char  allowipStr[215];
	strcpy(allowipStr,[allowip UTF8String]);
	
	char  accessStr[215];
	strcpy(accessStr,[proto UTF8String]);
	strcat(accessStr,"/");
	strcat(accessStr,[port UTF8String]);
	
	char  serverStr[215];
	strcpy(serverStr,[server UTF8String]);
	
	char  keyStr[215];
	strcpy(keyStr,[key UTF8String]);
	
	char  timeoutStr[215];
	strcpy(timeoutStr,[timeout UTF8String]);
	
	
	int res = run_fwknop(allowipStr, accessStr, serverStr, keyStr, timeoutStr);
	return res;
}

- (void)save
{
	//allowip
    UITextField *textField1 = (UITextField *)[[self view] viewWithTag:1];
    NSString *text = [textField1 text];
    
    [textField1 resignFirstResponder];
    
    NSLog(@"TextField: %@\nValue: %@", textField1, text);
    
    UITextField *textField2 = (UITextField *)[[self view] viewWithTag:2];
    //[textField2 setText:text];
	
	
	//proto
	UITextField *textFieldproto = (UITextField *)[[self view] viewWithTag:4];
	NSString *textProto = [textFieldproto text];
	
	//port
	UITextField *textFieldport = (UITextField *)[[self view] viewWithTag:5];
	NSString *textPort = [textFieldport text];

	//server
	UITextField *textFieldserver = (UITextField *)[[self view] viewWithTag:6];
	NSString *textServer = [textFieldserver text];
    	
	//key
	UITextField *textFieldkey = (UITextField *)[[self view] viewWithTag:7];
	NSString *textKey = [textFieldkey text];
    	
	
	//timeout
	UITextField *textFieldtimeout = (UITextField *)[[self view] viewWithTag:8];
	NSString *textTimeout = [textFieldtimeout text];
	
	int res = sendSPA(text, textProto, textPort, textServer, textKey, textTimeout );
    if(res > 0)
		
		[textField2 setText:@"PACKET SENT"];
	else
		[textField2 setText:@"ERROR"];
	
	[self setItemValue:@""];

}

#pragma mark -
#pragma mark UITextFieldDelegate Protocol

- (BOOL)textFieldShouldReturn:(UITextField *)textField
{
    NSLog(@"In %s -- calling save", _cmd);
	[textField resignFirstResponder];
    //[self save];
    
    return YES;
}

@end
