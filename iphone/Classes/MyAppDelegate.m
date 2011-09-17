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
#import "MyAppDelegate.h"
#import "FwknopController.h"

@implementation MyAppDelegate

@synthesize window = _window;
@synthesize viewController = _viewController;

- (void)dealloc 
{
    [_window release];
    [super dealloc];
}

- (void)applicationDidFinishLaunching:(UIApplication *)application
{
    CGRect windowRect = [[UIScreen mainScreen] bounds];
    UIWindow *window = [[UIWindow alloc] initWithFrame:windowRect];
    [window setBackgroundColor:[UIColor grayColor]];
    [self setWindow:window];
    
    EditableViewController *viewController = [[EditableViewController alloc]
                                              initWithNibName:nil
                                              bundle:nil];
    
    [self setViewController:viewController];
    
    [window addSubview:[viewController view]];
    [window makeKeyAndVisible];
    
    [viewController release];
    [window release];
}

@end
