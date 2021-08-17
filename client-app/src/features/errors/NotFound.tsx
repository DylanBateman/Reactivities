import React from 'react'
import { Link } from 'react-router-dom'
import { Button, Header, Icon, Segment } from 'semantic-ui-react'

export default function NotFound() 
{
    return (
        <Segment placeholder>
            <Header icon>
                <Icon name='search' />
                We could not find what you are looking for.
            </Header>
            <Segment.Inline>
                <Button as={Link} to='/activities' primary>
                    Return to Activities
                </Button>
            </Segment.Inline>
        </Segment>
    )
}